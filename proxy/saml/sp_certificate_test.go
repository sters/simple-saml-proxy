package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPCertificateCache(t *testing.T) {
	cache := NewSPCertificateCache()

	// Create a test certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	// Test Set and Get
	entityID := "https://sp.example.com"
	cache.Set(entityID, cert)

	retrieved, ok := cache.Get(entityID)
	assert.True(t, ok)
	assert.Equal(t, cert, retrieved)

	// Test Get for non-existent entity
	_, ok = cache.Get("https://nonexistent.example.com")
	assert.False(t, ok)
}

func TestExtractSigningCertificateFromMetadata(t *testing.T) {
	// Generate a test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "sp.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certBase64 := base64.StdEncoding.EncodeToString(certDER)

	tests := []struct {
		name        string
		metadata    string
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid metadata with signing certificate",
			metadata: fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`, certBase64),
			wantErr: false,
		},
		{
			name: "Valid metadata with certificate without use attribute",
			metadata: fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`, certBase64),
			wantErr: false,
		},
		{
			name: "Metadata with encryption certificate only",
			metadata: fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`, certBase64),
			wantErr:     true,
			errContains: "no signing certificate found",
		},
		{
			name: "Metadata without certificates",
			metadata: `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`,
			wantErr:     true,
			errContains: "no signing certificate found",
		},
		{
			name:        "Invalid XML",
			metadata:    `not valid xml`,
			wantErr:     true,
			errContains: "failed to unmarshal metadata",
		},
		{
			name: "Invalid certificate data",
			metadata: `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>invalid-base64-data!</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`,
			wantErr:     true,
			errContains: "no signing certificate found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := extractSigningCertificateFromMetadata([]byte(tt.metadata))

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cert)
				assert.Equal(t, "sp.example.com", cert.Subject.CommonName)
			}
		})
	}
}

func TestGetSPSigningCertificateFromMetadata(t *testing.T) {
	// Generate a test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "sp.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certBase64 := base64.StdEncoding.EncodeToString(certDER)

	// Create test metadata
	metadata := fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`, certBase64)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(metadata))
	}))
	defer server.Close()

	// Create test config
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
					EntityID:    "https://sp.example.com",
					MetadataURL: server.URL,
				},
			},
		},
	}

	cache := NewSPCertificateCache()

	// Test successful retrieval
	cert, err := GetSPSigningCertificateFromMetadata(t.Context(), cfg, "https://sp.example.com", cache)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "sp.example.com", cert.Subject.CommonName)

	// Test cache hit
	cert2, err := GetSPSigningCertificateFromMetadata(t.Context(), cfg, "https://sp.example.com", cache)
	require.NoError(t, err)
	assert.Equal(t, cert, cert2)

	// Test SP not in allowed list
	_, err = GetSPSigningCertificateFromMetadata(t.Context(), cfg, "https://unknown.example.com", cache)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SP not found in allowed list")

	// Test SP without metadata URL
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{
			EntityID: "https://sp2.example.com",
		},
	}
	_, err = GetSPSigningCertificateFromMetadata(t.Context(), cfg, "https://sp2.example.com", cache)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no metadata URL configured")
}

func TestExtractCertificateFromKeyDescriptor(t *testing.T) {
	// Generate a test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	// Test with DER-encoded certificate
	certBase64 := base64.StdEncoding.EncodeToString(certDER)
	keyDesc := saml.KeyDescriptor{
		KeyInfo: saml.KeyInfo{
			X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{
					{Data: certBase64},
				},
			},
		},
	}

	cert, err := extractCertificateFromKeyDescriptor(keyDesc)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test.example.com", cert.Subject.CommonName)

	// Test with PEM-encoded certificate
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	keyDescPEM := saml.KeyDescriptor{
		KeyInfo: saml.KeyInfo{
			X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{
					{Data: string(pemData)},
				},
			},
		},
	}

	cert2, err := extractCertificateFromKeyDescriptor(keyDescPEM)
	require.NoError(t, err)
	assert.NotNil(t, cert2)
	assert.Equal(t, "test.example.com", cert2.Subject.CommonName)
}
