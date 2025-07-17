package proxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSPSigningCertificateIntegration(t *testing.T) {
	// Generate a test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-sp.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certBase64 := base64.StdEncoding.EncodeToString(certDER)

	// Create test metadata with certificate
	metadata := fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://test-sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://test-sp.example.com/acs" index="0"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test-sp.example.com/slo" />
  </SPSSODescriptor>
</EntityDescriptor>`, certBase64)

	// Create test server to serve metadata
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(metadata))
	}))
	defer server.Close()

	// Create test configuration with SP metadata URL
	cfg := config.Config{
		Proxy: struct {
			EntityID                    string            `env:"ENTITY_ID"                      envDefault:"http://localhost:8080"`
			AcsURL                      string            `env:"ACS_URL"                        envDefault:"http://localhost:8080/sso/acs"`
			MetadataURL                 string            `env:"METADATA_URL"                   envDefault:"http://localhost:8080/metadata"`
			SLOURL                      string            `env:"SLO_URL"                        envDefault:"http://localhost:8080/slo"`
			SLSURL                      string            `env:"SLS_URL"                        envDefault:"http://localhost:8080/sls"`
			PrivateKeyPath              string            `env:"PRIVATE_KEY_PATH,required"`
			CertificatePath             string            `env:"CERTIFICATE_PATH,required"`
			RequireSignedLogoutRequests bool              `env:"REQUIRE_SIGNED_LOGOUT_REQUESTS" envDefault:"false"`
			AllowedSP                   []config.SPConfig `envPrefix:"ALLOWED_SP_"`
		}{
			AllowedSP: []config.SPConfig{
				{
					EntityID:    "https://test-sp.example.com",
					MetadataURL: server.URL,
				},
			},
		},
	}

	// Create test certificates and keys
	// Use the project's test certificates
	certPath := filepath.Join("..", "e2e", "proxy.crt")
	keyPath := filepath.Join("..", "e2e", "proxy.key")

	// Verify files exist
	_, err = os.Stat(certPath)
	require.NoError(t, err, "Test certificate file not found")
	_, err = os.Stat(keyPath)
	require.NoError(t, err, "Test key file not found")

	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Create storage and IDP
	storage, err := saml.NewStorage(cfg)
	require.NoError(t, err)

	idp := &saml.IDP{
		EntityID:   "https://proxy.example.com",
		IDPStorage: storage,
	}

	// Test successful certificate retrieval
	cert, err := getSPSigningCertificate(t.Context(), idp, "https://test-sp.example.com")
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test-sp.example.com", cert.Subject.CommonName)

	// Test cache hit (should be faster)
	start := time.Now()
	cert2, err := getSPSigningCertificate(t.Context(), idp, "https://test-sp.example.com")
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, cert, cert2)
	assert.Less(t, elapsed, 10*time.Millisecond, "Cache hit should be fast")

	// Test SP not in allowed list
	_, err = getSPSigningCertificate(t.Context(), idp, "https://unknown-sp.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SP not found in allowed list")

	// Test SP without metadata URL
	cfg.Proxy.AllowedSP = append(cfg.Proxy.AllowedSP, config.SPConfig{
		EntityID: "https://sp-no-metadata.example.com",
	})
	storage2, err := saml.NewStorage(cfg)
	require.NoError(t, err)
	idp.IDPStorage = storage2

	_, err = getSPSigningCertificate(t.Context(), idp, "https://sp-no-metadata.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no metadata URL configured")
}

func TestValidateRedirectSignatureWithRealCertificate(t *testing.T) {
	// Generate a test certificate and key for SP
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "sp-signer.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Create test data
	samlRequest := base64.StdEncoding.EncodeToString([]byte(`<LogoutRequest>test</LogoutRequest>`))
	relayState := "test-relay-state"
	sigAlg := sigAlgSHA256

	// Create signed data
	signedData := fmt.Sprintf("SAMLRequest=%s&RelayState=%s&SigAlg=%s", samlRequest, relayState, sigAlg)

	// Sign the data
	h := crypto.SHA256.New()
	h.Write([]byte(signedData))
	digest := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	require.NoError(t, err)

	// Test valid signature
	err = verifyRedirectSignature([]byte(signedData), signature, cert, sigAlg)
	require.NoError(t, err)

	// Test invalid signature (modify one byte)
	invalidSignature := make([]byte, len(signature))
	copy(invalidSignature, signature)
	invalidSignature[0] ^= 0xFF

	err = verifyRedirectSignature([]byte(signedData), invalidSignature, cert, sigAlg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")

	// Test wrong algorithm
	err = verifyRedirectSignature([]byte(signedData), signature, cert, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signature algorithm")
}
