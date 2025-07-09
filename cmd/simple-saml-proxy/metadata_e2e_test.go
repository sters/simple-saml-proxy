package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadataEndpoint(t *testing.T) {
	// Setup test certificates
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	// Create test configuration
	cfg := proxy.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	cfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	cfg.Proxy.PrivateKeyPath = proxyKeyPath
	cfg.Proxy.CertificatePath = proxyCertPath
	cfg.Proxy.AllowedSP = []proxy.SPConfig{
		{EntityID: "https://sp.example.com"},
	}

	// Create mock IDP
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	cfg.IDP = []proxy.IDPConfig{
		{
			ID:          "test-idp",
			MetadataURL: mockProvider.server.URL + "/saml/metadata",
		},
	}

	// Create the proxy
	ctx := t.Context()
	providers, err := proxy.CreateServiceProviders(ctx, cfg)
	require.NoError(t, err)

	idp, err := proxy.CreateProxyIDP(cfg)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, cfg)

	// Start test server
	server := httptest.NewServer(mux)
	defer server.Close()

	// Test metadata endpoint
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metadata", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/xml; charset=utf-8", resp.Header.Get("Content-Type"))

	// Parse metadata
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Check that we got valid XML
	assert.Contains(t, string(body), "EntityDescriptor")
	assert.Contains(t, string(body), cfg.Proxy.EntityID)

	// The zitadel/saml library uses a different metadata format, so we'll just check key elements
	assert.Contains(t, string(body), "IDPSSODescriptor")
	assert.Contains(t, string(body), "SingleSignOnService")

	// Check for key descriptor with certificate
	assert.Contains(t, string(body), "KeyDescriptor")
	assert.Contains(t, string(body), "X509Certificate")
}
