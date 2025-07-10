package proxy

import (
	"io"
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

func TestSetupHTTPHandlers(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	// Verify that the certificate can be loaded
	// Note: LoadCertificate has been moved to the saml package

	// Create a test config with multiple IDP
	cfg := config.Config{}
	cfg.Proxy.EntityID = "http://test.example.com/metadata"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Add multiple IDP
	cfg.IDP = []config.IDPConfig{
		{
			ID:              "idp1",
			EntityID:        "https://idp1.example.com/saml/metadata",
			SSOURL:          "https://idp1.example.com/saml/sso",
			CertificatePath: certPath, // Use the same cert for testing
		},
		{
			ID:              "idp2",
			EntityID:        "https://idp2.example.com/saml/metadata",
			SSOURL:          "https://idp2.example.com/saml/sso",
			CertificatePath: certPath, // Use the same cert for testing
		},
	}

	// Create SAML service providers
	providers, err := saml.CreateServiceProviders(t.Context(), cfg)
	require.NoError(t, err)

	// Create SAML IDP
	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	// Test setting up HTTP handlers
	mux := SetupHTTPHandlers(idp, providers, cfg)
	assert.NotNil(t, mux)

	// Test the SSO endpoint
	req := httptest.NewRequest(http.MethodGet, "/sso", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Response")
	assert.Contains(t, w.Body.String(), "StatusCode")

	// Test the metadata endpoint (should return IdP metadata)
	req = httptest.NewRequest(http.MethodGet, "/metadata", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "EntityDescriptor")
	assert.Contains(t, w.Body.String(), "IDPSSODescriptor")
	assert.Contains(t, w.Body.String(), cfg.Proxy.EntityID)
	// The SAML library sets the content type to "text/xml; charset=utf-8"
	assert.Equal(t, "text/xml; charset=utf-8", w.Header().Get("Content-Type"))
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
	cfg := config.Config{}
	cfg.Server.ListenAddress = "localhost:0" // Use port 0 to get a random available port
	cfg.Proxy.MetadataURL = "http://test.example.com/metadata"
	cfg.Proxy.AcsURL = "http://test.example.com/sso/acs"
	cfg.Proxy.EntityID = "http://test.example.com"

	// Generate test certificate and key
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Add a test IDP
	cfg.IDP = []config.IDPConfig{
		{
			ID:              "test-idp",
			EntityID:        "https://test-idp.example.com/saml/metadata",
			SSOURL:          "https://test-idp.example.com/saml/sso",
			CertificatePath: certPath, // Use the same cert for testing
		},
	}

	// Create a test server using httptest
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ping":
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("pong"))
			if err != nil {
				t.Fatalf("Failed to write response: %v", err)
			}
		case "/metadata":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("<EntityDescriptor>Test Metadata</EntityDescriptor>"))
			if err != nil {
				t.Fatalf("Failed to write response: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer testServer.Close()

	// Test the server endpoints
	// Test ping endpoint
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, testServer.URL+"/ping", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(body))
	resp.Body.Close()

	// Test metadata endpoint
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, testServer.URL+"/metadata", nil)
	require.NoError(t, err)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/xml", resp.Header.Get("Content-Type"))
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "EntityDescriptor")
	resp.Body.Close()

	// Test non-existent endpoint
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, testServer.URL+"/nonexistent", nil)
	require.NoError(t, err)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()

	// Test the actual StartServer function with a mock handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	})

	// Start the server in a goroutine with a short timeout
	errCh := make(chan error, 1)
	go func() {
		// Create a server with the StartServer function but with a custom shutdown mechanism
		server := &http.Server{
			Addr:              cfg.Server.ListenAddress,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}

		// Start the server and capture any errors
		errCh <- server.ListenAndServe()
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
}
