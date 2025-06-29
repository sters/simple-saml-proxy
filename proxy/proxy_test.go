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

	// Create a test config with multiple IDP
	config := Config{}
	config.Proxy.EntityID = "http://test.example.com/metadata"
	config.Proxy.AllowedServiceURLPrefix = []string{"https://example.com", "https://test.example.com"}

	// Add multiple IDP
	config.IDP = []IDPConfig{
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
	providers, err := CreateServiceProviders(config, cert)
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

	// Test the SSO endpoint with SAMLRequest parameter (should show IdP selection page)
	req = httptest.NewRequest(http.MethodGet, "/sso?SAMLRequest=request123", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Select an Identity Provider")
	assert.Contains(t, w.Body.String(), "idp1")
	assert.Contains(t, w.Body.String(), "idp2")

	// Test the SSO endpoint without SAMLRequest parameter (should return bad request)
	req = httptest.NewRequest(http.MethodGet, "/sso", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing SAMLRequest parameter")

	// Test the metadata endpoint (should return IdP metadata)
	req = httptest.NewRequest(http.MethodGet, "/metadata", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "EntityDescriptor")
	assert.Contains(t, w.Body.String(), "IDPSSODescriptor")
	assert.Contains(t, w.Body.String(), config.Proxy.EntityID)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	// Test the select_idp endpoint for idp1
	req = httptest.NewRequest(http.MethodGet, "/select_idp/idp1?SAMLRequest=request123&RelayState=state123", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code)
	redirectURL := w.Header().Get("Location")
	assert.Contains(t, redirectURL, "https://idp1.example.com/saml/sso")
	assert.Contains(t, redirectURL, "SAMLRequest=request123")
	assert.Contains(t, redirectURL, "RelayState=state123")

	// Test the select_idp endpoint with an invalid IDP
	req = httptest.NewRequest(http.MethodGet, "/select_idp/invalid?SAMLRequest=request123", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid IDP ID")

	// Test the idp-initiated endpoint
	req = httptest.NewRequest(http.MethodGet, "/idp-initiated", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Contains(t, w.Body.String(), "IdP-Initiated flow not yet implemented")
}

func TestServiceURLValidation(t *testing.T) {
	// Test with allowed prefixes
	allowedPrefixes := []string{"https://example.com", "https://test.example.com"}

	// URL that matches an allowed prefix
	assert.True(t, isAllowedServiceURL("https://example.com/path", allowedPrefixes))

	// URL that doesn't match any allowed prefix
	assert.False(t, isAllowedServiceURL("https://malicious.com", allowedPrefixes))

	// Test with no allowed prefixes (all URLs are allowed)
	assert.True(t, isAllowedServiceURL("https://any.domain.com", nil))
	assert.True(t, isAllowedServiceURL("https://any.domain.com", []string{}))
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
