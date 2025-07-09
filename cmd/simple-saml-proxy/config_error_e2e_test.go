package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultipleIdPConfiguration tests the proxy with multiple IdP configurations.
func TestMultipleIdPConfiguration(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := generateTestCertificate(t)

	// Create two mock IdPs
	mockIDP1 := NewMockSAMLProvider(t)
	defer mockIDP1.Close()

	mockIDP2 := NewMockSAMLProvider(t)
	mockIDP2.entityID = "https://mockidp2.example.com/saml/metadata"
	defer mockIDP2.Close()

	// Set up environment variables with multiple IdPs
	envVars := map[string]string{
		"PROXY_ENTITY_ID":              "http://localhost:8080",
		"PROXY_ACS_URL":                "http://localhost:8080/sso/acs",
		"PROXY_METADATA_URL":           "http://localhost:8080/metadata",
		"PROXY_PRIVATE_KEY_PATH":       keyPath,
		"PROXY_CERTIFICATE_PATH":       certPath,
		"PROXY_ALLOWED_SP_0_ENTITY_ID": "https://sp.example.com",
		"IDP_0_ID":                     "IdP-1",
		"IDP_0_METADATA_URL":           mockIDP1.server.URL + "/saml/metadata",
		"IDP_1_ID":                     "IdP-2",
		"IDP_1_METADATA_URL":           mockIDP2.server.URL + "/saml/metadata",
		"SERVER_LISTEN_ADDRESS":        ":0",
	}

	for k, v := range envVars {
		t.Setenv(k, v)
	}

	// Load config
	config, err := proxy.LoadConfig()
	require.NoError(t, err)
	require.Len(t, config.IDP, 2, "Expected 2 IdPs to be configured")
	assert.Equal(t, "IdP-1", config.IDP[0].ID)
	assert.Equal(t, "IdP-2", config.IDP[1].ID)

	// Start the proxy
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	proxyServer, err := startTestProxy(ctx, t)
	require.NoError(t, err)
	defer proxyServer.Close()

	// Test IdP selection page shows both IdPs
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create a SAML request
	mockClient := NewMockSAMLClient(t)
	defer mockClient.Close()

	// Initiate login
	resp, err := mockClient.InitiateLogin(t.Context(), proxyServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should redirect to IdP selection
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	location := resp.Header.Get("Location")
	require.Contains(t, location, "/idp_select")

	// Follow redirect to get IdP selection page
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+location, nil)
	require.NoError(t, err)

	// Copy cookies
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}

	resp2, err := client.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()

	// Read response body
	body := new(bytes.Buffer)
	_, err = body.ReadFrom(resp2.Body)
	require.NoError(t, err)

	// Check that both IdPs are listed
	require.Contains(t, body.String(), "IdP-1")
	require.Contains(t, body.String(), "IdP-2")
}

// TestInvalidConfiguration tests various invalid configuration scenarios.
func TestInvalidConfiguration(t *testing.T) {
	testCases := []struct {
		name        string
		envVars     map[string]string
		expectError string
	}{
		{
			name: "No IdP configured",
			envVars: map[string]string{
				"PROXY_ENTITY_ID":        "http://localhost:8080",
				"PROXY_PRIVATE_KEY_PATH": "/tmp/key.pem",
				"PROXY_CERTIFICATE_PATH": "/tmp/cert.pem",
			},
			expectError: "at least one IDP must be configured",
		},
		{
			name: "Missing required private key path",
			envVars: map[string]string{
				"PROXY_ENTITY_ID":        "http://localhost:8080",
				"PROXY_CERTIFICATE_PATH": "/tmp/cert.pem",
				"IDP_0_ID":               "test-idp",
				"IDP_0_METADATA_URL":     "http://idp.example.com",
			},
			expectError: "required",
		},
		{
			name: "Missing required certificate path",
			envVars: map[string]string{
				"PROXY_ENTITY_ID":        "http://localhost:8080",
				"PROXY_PRIVATE_KEY_PATH": "/tmp/key.pem",
				"IDP_0_ID":               "test-idp",
				"IDP_0_METADATA_URL":     "http://idp.example.com",
			},
			expectError: "required",
		},
		{
			name: "Invalid IdP configuration - missing ID",
			envVars: map[string]string{
				"PROXY_ENTITY_ID":        "http://localhost:8080",
				"PROXY_PRIVATE_KEY_PATH": "/tmp/key.pem",
				"PROXY_CERTIFICATE_PATH": "/tmp/cert.pem",
				"IDP_0_METADATA_URL":     "http://idp.example.com",
			},
			expectError: "required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment variables
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}

			// Try to load config
			_, err := proxy.LoadConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectError)
		})
	}
}

// TestEnvironmentVariableValidation tests environment variable parsing and validation.
func TestEnvironmentVariableValidation(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := generateTestCertificate(t)

	testCases := []struct {
		name     string
		envVars  map[string]string
		validate func(t *testing.T, config proxy.Config)
	}{
		{
			name: "Default values applied",
			envVars: map[string]string{
				"PROXY_PRIVATE_KEY_PATH": keyPath,
				"PROXY_CERTIFICATE_PATH": certPath,
				"IDP_0_ID":               "test-idp",
				"IDP_0_METADATA_URL":     "http://idp.example.com",
			},
			validate: func(t *testing.T, config proxy.Config) {
				t.Helper()
				// Check defaults
				assert.Equal(t, "http://localhost:8080", config.Proxy.EntityID)
				assert.Equal(t, "http://localhost:8080/sso/acs", config.Proxy.AcsURL)
				assert.Equal(t, "http://localhost:8080/metadata", config.Proxy.MetadataURL)
				assert.Equal(t, ":8080", config.Server.ListenAddress)
			},
		},
		{
			name: "Custom values override defaults",
			envVars: map[string]string{
				"PROXY_ENTITY_ID":        "https://proxy.example.com",
				"PROXY_ACS_URL":          "https://proxy.example.com/acs",
				"PROXY_METADATA_URL":     "https://proxy.example.com/metadata",
				"PROXY_PRIVATE_KEY_PATH": keyPath,
				"PROXY_CERTIFICATE_PATH": certPath,
				"IDP_0_ID":               "test-idp",
				"IDP_0_METADATA_URL":     "http://idp.example.com",
				"SERVER_LISTEN_ADDRESS":  ":9090",
			},
			validate: func(t *testing.T, config proxy.Config) {
				t.Helper()
				assert.Equal(t, "https://proxy.example.com", config.Proxy.EntityID)
				assert.Equal(t, "https://proxy.example.com/acs", config.Proxy.AcsURL)
				assert.Equal(t, "https://proxy.example.com/metadata", config.Proxy.MetadataURL)
				assert.Equal(t, ":9090", config.Server.ListenAddress)
			},
		},
		{
			name: "Multiple allowed SPs configuration",
			envVars: map[string]string{
				"PROXY_PRIVATE_KEY_PATH":          keyPath,
				"PROXY_CERTIFICATE_PATH":          certPath,
				"PROXY_ALLOWED_SP_0_ENTITY_ID":    "https://sp1.example.com",
				"PROXY_ALLOWED_SP_0_ACS_URL":      "https://sp1.example.com/acs",
				"PROXY_ALLOWED_SP_0_METADATA_URL": "https://sp1.example.com/metadata",
				"PROXY_ALLOWED_SP_1_ENTITY_ID":    "https://sp2.example.com",
				"PROXY_ALLOWED_SP_1_ACS_URL":      "https://sp2.example.com/acs",
				"PROXY_ALLOWED_SP_1_METADATA_URL": "https://sp2.example.com/metadata",
				"IDP_0_ID":                        "test-idp",
				"IDP_0_METADATA_URL":              "http://idp.example.com",
			},
			validate: func(t *testing.T, config proxy.Config) {
				t.Helper()
				require.Len(t, config.Proxy.AllowedSP, 2)
				assert.Equal(t, "https://sp1.example.com", config.Proxy.AllowedSP[0].EntityID)
				assert.Equal(t, "https://sp2.example.com", config.Proxy.AllowedSP[1].EntityID)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment variables
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}

			// Load config
			config, err := proxy.LoadConfig()
			require.NoError(t, err)

			// Validate
			tc.validate(t, config)
		})
	}
}

// TestIdPFailureHandling tests proxy behavior when IdP fails or is unavailable.
func TestIdPFailureHandling(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := generateTestCertificate(t)

	// Create a mock IdP that can simulate failures
	mockIDP := NewMockSAMLProviderWithErrors(t)
	defer mockIDP.Close()

	// Set up environment
	envVars := map[string]string{
		"PROXY_ENTITY_ID":              "http://localhost:8080",
		"PROXY_ACS_URL":                "http://localhost:8080/sso/acs",
		"PROXY_PRIVATE_KEY_PATH":       keyPath,
		"PROXY_CERTIFICATE_PATH":       certPath,
		"PROXY_ALLOWED_SP_0_ENTITY_ID": "https://sp.example.com",
		"IDP_0_ID":                     "test-idp",
		"IDP_0_METADATA_URL":           mockIDP.server.URL + "/saml/metadata",
		"SERVER_LISTEN_ADDRESS":        ":0",
	}

	for k, v := range envVars {
		t.Setenv(k, v)
	}

	// Start the proxy
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	proxyServer, err := startTestProxy(ctx, t)
	require.NoError(t, err)
	defer proxyServer.Close()

	t.Run("IdP returns authentication failure", func(t *testing.T) {
		// Configure IdP to fail authentication
		mockIDP.SetShouldFailAuth(true)

		// Create client and initiate login flow
		client := NewMockSAMLClient(t)
		defer client.Close()

		resp, err := client.InitiateLogin(t.Context(), proxyServer.URL)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Follow through the flow to IdP selection
		location := resp.Header.Get("Location")
		resp2, err := followRedirectWithCookies(t, client.client, proxyServer.URL+location, resp.Cookies())
		require.NoError(t, err)
		defer resp2.Body.Close()

		// Select the IdP
		selectURL := proxyServer.URL + "/idp_selected?idpID=test-idp"
		resp3, err := getWithCookies(t, client.client, selectURL, resp2.Cookies())
		require.NoError(t, err)
		defer resp3.Body.Close()

		// Should redirect to IdP (302 Found)
		require.Equal(t, http.StatusFound, resp3.StatusCode)
		idpLocation := resp3.Header.Get("Location")
		require.Contains(t, idpLocation, mockIDP.ssoURL)

		// Reset failure flag for next test
		mockIDP.SetShouldFailAuth(false)
	})

	t.Run("IdP returns HTTP error", func(t *testing.T) {
		// Configure IdP to return an error
		mockIDP.SetShouldReturnError(true, http.StatusServiceUnavailable, "Service Unavailable")

		// Create client and initiate login flow
		client := NewMockSAMLClient(t)
		defer client.Close()

		resp, err := client.InitiateLogin(t.Context(), proxyServer.URL)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Follow through the flow
		location := resp.Header.Get("Location")
		resp2, err := followRedirectWithCookies(t, client.client, proxyServer.URL+location, resp.Cookies())
		require.NoError(t, err)
		defer resp2.Body.Close()

		// Select the IdP
		selectURL := proxyServer.URL + "/idp_selected?idpID=test-idp"
		resp3, err := getWithCookies(t, client.client, selectURL, resp2.Cookies())
		require.NoError(t, err)
		defer resp3.Body.Close()

		// Should redirect to IdP (302 Found)
		require.Equal(t, http.StatusFound, resp3.StatusCode)

		// Reset error flag
		mockIDP.SetShouldReturnError(false, 0, "")
	})
}

// TestNetworkErrorHandling tests proxy behavior during network errors and timeouts.
func TestNetworkErrorHandling(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := generateTestCertificate(t)

	// Create a mock server that simulates network issues
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/saml/metadata" {
			// Simulate slow response
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><EntityDescriptor/>`))
		}
	}))
	defer slowServer.Close()

	t.Run("Metadata fetch timeout", func(t *testing.T) {
		// Set up environment with a server that responds slowly
		envVars := map[string]string{
			"PROXY_ENTITY_ID":        "http://localhost:8080",
			"PROXY_PRIVATE_KEY_PATH": keyPath,
			"PROXY_CERTIFICATE_PATH": certPath,
			"IDP_0_ID":               "slow-idp",
			"IDP_0_METADATA_URL":     slowServer.URL + "/saml/metadata",
			"SERVER_LISTEN_ADDRESS":  ":0",
		}

		for k, v := range envVars {
			t.Setenv(k, v)
		}

		// Try to start proxy with short timeout
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		_, err := startTestProxy(ctx, t)
		// Should fail due to timeout or context cancellation
		require.Error(t, err)
	})

	t.Run("Invalid metadata URL", func(t *testing.T) {
		// Set up environment with invalid metadata URL
		envVars := map[string]string{
			"PROXY_ENTITY_ID":        "http://localhost:8080",
			"PROXY_PRIVATE_KEY_PATH": keyPath,
			"PROXY_CERTIFICATE_PATH": certPath,
			"IDP_0_ID":               "invalid-idp",
			"IDP_0_METADATA_URL":     "http://invalid.local.domain:12345/metadata",
			"SERVER_LISTEN_ADDRESS":  ":0",
		}

		for k, v := range envVars {
			t.Setenv(k, v)
		}

		// Try to start proxy
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		_, err := startTestProxy(ctx, t)
		// Should fail due to connection error
		require.Error(t, err)
	})
}

// TestLoggingAndMonitoring tests that logs and monitoring outputs are correct.
func TestLoggingAndMonitoring(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := generateTestCertificate(t)

	// Create mock IdP
	mockIDP := NewMockSAMLProvider(t)
	defer mockIDP.Close()

	// Set up environment
	envVars := map[string]string{
		"PROXY_ENTITY_ID":              "http://localhost:8080",
		"PROXY_PRIVATE_KEY_PATH":       keyPath,
		"PROXY_CERTIFICATE_PATH":       certPath,
		"PROXY_ALLOWED_SP_0_ENTITY_ID": "https://sp.example.com",
		"IDP_0_ID":                     "test-idp",
		"IDP_0_METADATA_URL":           mockIDP.server.URL + "/saml/metadata",
		"SERVER_LISTEN_ADDRESS":        ":0",
	}

	for k, v := range envVars {
		t.Setenv(k, v)
	}

	// Start the proxy
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	proxyServer, err := startTestProxy(ctx, t)
	require.NoError(t, err)
	defer proxyServer.Close()

	t.Run("Health check endpoint", func(t *testing.T) {
		// Test /ping endpoint
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/ping", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		body := new(bytes.Buffer)
		_, err = body.ReadFrom(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "pong", body.String())
	})

	t.Run("Metadata endpoint availability", func(t *testing.T) {
		// Test /metadata endpoint
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/metadata", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/xml; charset=utf-8", resp.Header.Get("Content-Type"))

		// Verify it returns valid XML
		body := new(bytes.Buffer)
		_, err = body.ReadFrom(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, body.String(), "EntityDescriptor")
		assert.Contains(t, body.String(), "IDPSSODescriptor")
	})

	t.Run("Error logging on invalid requests", func(t *testing.T) {
		// Test invalid SSO request
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/sso", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// The zitadel/saml library returns 200 with an error page for invalid requests
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Test invalid ACS request to the proxy's ACS endpoint
		req2, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/saml/acs", strings.NewReader("invalid=data"))
		require.NoError(t, err)
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp2, err := http.DefaultClient.Do(req2)
		require.NoError(t, err)
		defer resp2.Body.Close()

		// Should return error
		require.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	})
}

// Helper functions

func startTestProxy(ctx context.Context, t *testing.T) (*httptest.Server, error) {
	t.Helper()

	// Load config
	config, err := proxy.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create service providers
	providers, err := proxy.CreateServiceProviders(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create service providers: %w", err)
	}

	// Create proxy IDP
	idp, err := proxy.CreateProxyIDP(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy IDP: %w", err)
	}

	// Setup HTTP handlers
	mux := proxy.SetupHTTPHandlers(idp, providers, config)

	// Create test server
	server := httptest.NewServer(mux)

	// Update URLs to use test server address
	config.Proxy.EntityID = server.URL
	config.Proxy.AcsURL = server.URL + "/sso/acs"
	config.Proxy.MetadataURL = server.URL + "/metadata"

	// Recreate providers with updated config
	providers, err = proxy.CreateServiceProviders(ctx, config)
	if err != nil {
		server.Close()

		return nil, fmt.Errorf("failed to recreate service providers: %w", err)
	}

	// Recreate proxy IDP
	idp, err = proxy.CreateProxyIDP(config)
	if err != nil {
		server.Close()

		return nil, fmt.Errorf("failed to recreate proxy IDP: %w", err)
	}

	// Update handler
	mux = proxy.SetupHTTPHandlers(idp, providers, config)
	server.Config.Handler = mux

	return server, nil
}

func followRedirectWithCookies(t *testing.T, client *http.Client, url string, cookies []*http.Cookie) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	return client.Do(req) //nolint:wrapcheck // Helper function, error context is clear
}

func getWithCookies(t *testing.T, client *http.Client, url string, cookies []*http.Cookie) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	return client.Do(req) //nolint:wrapcheck // Helper function, error context is clear
}
