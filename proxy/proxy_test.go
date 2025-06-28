package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificate generates a self-signed certificate and private key for testing.
func generateTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	var certPath, keyPath string
	tempDir := t.TempDir()

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Write the certificate to a file
	certPath = filepath.Join(tempDir, "cert.pem")
	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(t, err)

	// Write the private key to a file
	keyPath = filepath.Join(tempDir, "key.pem")
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	require.NoError(t, err)

	return certPath, keyPath
}

func TestSetupHTTPHandlers(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	// Load the certificate
	cert, err := LoadCertificate(certPath, keyPath)
	require.NoError(t, err)

	// Create a test config with multiple IDPs
	config := Config{}
	config.Proxy.EntityID = "http://test.example.com/metadata"
	config.Proxy.CookieName = "idp_selection"

	// Add multiple IDPs
	config.IDPs = []IDPConfig{
		{
			ID:              "idp1",
			EntityID:        "https://idp1.example.com/saml/metadata",
			SSOURL:          "https://idp1.example.com/saml/sso",
			CertificatePath: "/path/to/idp1.crt",
		},
		{
			ID:              "idp2",
			EntityID:        "https://idp2.example.com/saml/metadata",
			SSOURL:          "https://idp2.example.com/saml/sso",
			CertificatePath: "/path/to/idp2.crt",
		},
	}

	// Create SAML service providers
	providers, err := CreateSAMLServiceProviders(config, cert)
	require.NoError(t, err)

	// Test setting up HTTP handlers
	mux := SetupHTTPHandlers(providers, config)
	assert.NotNil(t, mux)

	// Test the health check endpoint
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "pong", w.Body.String())

	// Test the SSO endpoint with no cookie (should use default IDP)
	req = httptest.NewRequest(http.MethodGet, "/sso", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://idp1.example.com/saml/sso", w.Header().Get("Location"))

	// Test the SSO endpoint with a cookie for idp2
	req = httptest.NewRequest(http.MethodGet, "/sso", nil)
	req.AddCookie(&http.Cookie{
		Name:  config.Proxy.CookieName,
		Value: "idp2",
	})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://idp2.example.com/saml/sso", w.Header().Get("Location"))

	// Test the metadata endpoint with no cookie (should use default IDP)
	req = httptest.NewRequest(http.MethodGet, "/metadata", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "EntityDescriptor")

	// Test the metadata endpoint with a cookie for idp2
	req = httptest.NewRequest(http.MethodGet, "/metadata", nil)
	req.AddCookie(&http.Cookie{
		Name:  config.Proxy.CookieName,
		Value: "idp2",
	})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "EntityDescriptor")

	// Test the link_sso endpoint for idp1
	req = httptest.NewRequest(http.MethodGet, "/link_sso/idp1?service=https://example.com", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://example.com", w.Header().Get("Location"))

	// Verify the cookie was set
	cookies := w.Result().Cookies()
	var idpCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == config.Proxy.CookieName {
			idpCookie = cookie

			break
		}
	}
	assert.NotNil(t, idpCookie)
	assert.Equal(t, "idp1", idpCookie.Value)

	// Test the link_sso endpoint with an invalid IDP
	req = httptest.NewRequest(http.MethodGet, "/link_sso/invalid", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestStartServer(t *testing.T) {
	// Create a test config
	config := Config{}
	config.Server.ListenAddress = "localhost:0" // Use port 0 to get a random available port
	config.Proxy.MetadataURL = "http://test.example.com/metadata"
	config.Proxy.AcsURL = "http://test.example.com/sso/acs"
	config.Proxy.EntityID = "http://test.example.com"

	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	})

	// Start the server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- StartServer(config, handler)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// The server should still be running (no error yet)
	select {
	case err := <-errCh:
		t.Fatalf("Server stopped unexpectedly: %v", err)
	default:
		// This is expected, server is still running
	}

	// We can't easily test the actual server without modifying the StartServer function
	// to accept a custom listener or to return the server for shutdown
}
