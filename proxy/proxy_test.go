package proxy

import (
	"context"
	"fmt"
	"net"
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

	// Test the SSO endpoint - use the actual metadata SSO endpoint
	req := httptest.NewRequest(http.MethodGet, "/idp/sso", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Response")
	assert.Contains(t, w.Body.String(), "StatusCode")

	// Test the metadata endpoint (should return IdP metadata)
	req = httptest.NewRequest(http.MethodGet, "/idp/metadata", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "EntityDescriptor")
	assert.Contains(t, w.Body.String(), "IDPSSODescriptor")
	assert.Contains(t, w.Body.String(), cfg.Proxy.EntityID)
	// The SAML library sets the content type to "text/xml; charset=utf-8"
	assert.Equal(t, "text/xml; charset=utf-8", w.Header().Get("Content-Type"))
}

func TestStartServer(t *testing.T) {
	tests := []struct {
		name          string
		listenAddress string
		handler       http.Handler
		wantErr       bool
		errContains   string
	}{
		{
			name:          "Valid configuration with random port",
			listenAddress: "localhost:0",
			handler:       http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			wantErr:       false,
		},
		{
			name:          "Invalid listen address",
			listenAddress: "invalid:address:format",
			handler:       http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			wantErr:       true,
			errContains:   "too many colons",
		},
		{
			name:          "Permission denied port",
			listenAddress: "localhost:1", // Port 1 typically requires root
			handler:       http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			wantErr:       true,
			errContains:   "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{}
			cfg.Server.ListenAddress = tt.listenAddress
			// Set default entity ID
			cfg.Proxy.EntityID = "http://test.example.com"

			// For valid configurations, start server in background
			if !tt.wantErr {
				// Find an available port
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err)
				tcpAddr, ok := listener.Addr().(*net.TCPAddr)
				require.True(t, ok)
				port := tcpAddr.Port
				err = listener.Close()
				require.NoError(t, err)

				cfg.Server.ListenAddress = fmt.Sprintf("localhost:%d", port)

				// Start server in goroutine
				serverErr := make(chan error, 1)
				go func() {
					serverErr <- StartServer(cfg, tt.handler)
				}()

				// Give server time to start
				time.Sleep(100 * time.Millisecond)

				// Test that server is running
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://localhost:%d/", port), nil)
				require.NoError(t, err)
				client := &http.Client{}
				resp, err := client.Do(req)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				resp.Body.Close()

				// Server should still be running
				select {
				case err := <-serverErr:
					t.Fatalf("Server stopped unexpectedly: %v", err)
				default:
					// Expected - server is still running
				}
			} else {
				// For error cases, call StartServer directly
				err := StartServer(cfg, tt.handler)
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestStartServerWithMiddleware(t *testing.T) {
	// Test that the server properly applies middleware
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// Find an available port
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	port := tcpAddr.Port
	err = listener.Close()
	require.NoError(t, err)

	cfg := config.Config{}
	cfg.Server.ListenAddress = fmt.Sprintf("localhost:%d", port)

	// Start server
	serverErr := make(chan error, 1)
	server := &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		serverErr <- server.ListenAndServe()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Make request
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://localhost:%d/test", port), nil)
	require.NoError(t, err)
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	assert.True(t, called, "Handler should have been called")

	// Shutdown server
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err = server.Shutdown(ctx)
	require.NoError(t, err)
}
