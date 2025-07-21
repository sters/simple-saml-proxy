package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSSOTest creates a common test setup for SSO tests.
func setupSSOTest(t *testing.T) (*config.Config, *httptest.Server, *MockSAMLProvider) {
	t.Helper()

	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	cfg := &config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	cfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	cfg.Proxy.PrivateKeyPath = proxyKeyPath
	cfg.Proxy.CertificatePath = proxyCertPath
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}

	mockProvider := NewMockSAMLProvider(t)

	cfg.IDP = []config.IDPConfig{
		{
			ID:          "test-idp",
			MetadataURL: mockProvider.server.URL + "/saml/metadata",
		},
		{
			ID:          "test-idp-2",
			MetadataURL: mockProvider.server.URL + "/saml/metadata",
		},
	}

	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, *cfg)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(*cfg)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, *cfg)
	server := httptest.NewServer(mux)

	return cfg, server, mockProvider
}

func TestSSOEndpoint_ValidSAMLRequest(t *testing.T) {
	cfg, server, mockProvider := setupSSOTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create a mock SAML request
	samlRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0" IssueInstant="2023-01-01T00:00:00Z">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded, err := encodeSAMLRequest(samlRequest)
	require.NoError(t, err)

	// Make request to SSO endpoint
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metadata/sso?SAMLRequest="+url.QueryEscape(encoded)+"&RelayState=test-state", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Should show IDP selection page
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, "Select an Identity Provider")
	assert.Contains(t, bodyStr, cfg.IDP[0].ID)
	assert.Contains(t, bodyStr, cfg.IDP[1].ID)
}

func TestSSOEndpoint_MissingSAMLRequest(t *testing.T) {
	_, server, mockProvider := setupSSOTest(t)
	defer server.Close()
	defer mockProvider.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metadata/sso", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, "RequestDenied")
}

func TestSSOEndpoint_InvalidSAMLRequest(t *testing.T) {
	_, server, mockProvider := setupSSOTest(t)
	defer server.Close()
	defer mockProvider.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metadata/sso?SAMLRequest=invalid-base64", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, "RequestDenied")
}

func TestSSOEndpoint_SingleIDPAutoRedirect(t *testing.T) {
	// Setup with single IDP
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	singleCfg := config.Config{}
	singleCfg.Proxy.EntityID = "https://proxy.example.com"
	singleCfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	singleCfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	singleCfg.Proxy.PrivateKeyPath = proxyKeyPath
	singleCfg.Proxy.CertificatePath = proxyCertPath
	singleCfg.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}

	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	singleCfg.IDP = []config.IDPConfig{
		{
			ID:          "test-idp",
			MetadataURL: mockProvider.server.URL + "/saml/metadata",
		},
	}

	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, singleCfg)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(singleCfg)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, singleCfg)
	singleServer := httptest.NewServer(mux)
	defer singleServer.Close()

	// Create SAML request
	samlRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0" IssueInstant="2023-01-01T00:00:00Z">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded, err := encodeSAMLRequest(samlRequest)
	require.NoError(t, err)

	// Use client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, singleServer.URL+"/metadata/sso?SAMLRequest="+url.QueryEscape(encoded)+"&RelayState=test-state", nil)
	resp, err := client.Do(req)
	require.NoError(t, err)

	// Should redirect to idp_select first
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.Contains(t, location, "/idp_select?id=")

	// Get cookies from first response
	cookies := resp.Cookies()
	resp.Body.Close()

	// Follow the redirect to idp_select
	req2, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, singleServer.URL+location, nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	resp2, err := client.Do(req2)
	require.NoError(t, err)

	// Should auto-redirect to idp_selected
	assert.Equal(t, http.StatusFound, resp2.StatusCode)
	location2 := resp2.Header.Get("Location")
	assert.Contains(t, location2, "/idp_selected?idpID=test-idp")

	// Get new cookies
	cookies = append(cookies, resp2.Cookies()...)
	resp2.Body.Close()

	// Follow the redirect to idp_selected
	req3, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, singleServer.URL+location2, nil)
	for _, c := range cookies {
		req3.AddCookie(c)
	}
	resp3, err := client.Do(req3)
	require.NoError(t, err)
	defer resp3.Body.Close()

	// Should now redirect to the actual IDP
	assert.Equal(t, http.StatusFound, resp3.StatusCode)
	location3 := resp3.Header.Get("Location")
	assert.Contains(t, location3, mockProvider.ssoURL)
	assert.Contains(t, location3, "SAMLRequest=")
	assert.Contains(t, location3, "RelayState=test-state")
}

func TestSSOEndpoint_RelayStatePreservation(t *testing.T) {
	_, server, mockProvider := setupSSOTest(t)
	defer server.Close()
	defer mockProvider.Close()

	samlRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0" IssueInstant="2023-01-01T00:00:00Z">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded, err := encodeSAMLRequest(samlRequest)
	require.NoError(t, err)

	customRelayState := "my-custom-relay-state-12345"
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metadata/sso?SAMLRequest="+url.QueryEscape(encoded)+"&RelayState="+url.QueryEscape(customRelayState), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check that relay state is preserved in the selection form
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, customRelayState)
}

func TestSSOEndpoint_MultipleIDPsSelection(t *testing.T) {
	_, server, mockProvider := setupSSOTest(t)
	defer server.Close()
	defer mockProvider.Close()

	samlRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0" IssueInstant="2023-01-01T00:00:00Z">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded, err := encodeSAMLRequest(samlRequest)
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metadata/sso?SAMLRequest="+url.QueryEscape(encoded), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)

	// Should show both IDPs
	assert.Contains(t, bodyStr, "test-idp")
	assert.Contains(t, bodyStr, "test-idp-2")
	assert.Contains(t, bodyStr, "/idp_selected")

	// Should have auth request cookie
	cookies := resp.Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "authID" {
			authCookie = c

			break
		}
	}
	if assert.NotNil(t, authCookie, "Should set auth request cookie") {
		assert.NotEmpty(t, authCookie.Value)
	}
}

func TestSSOEndpoint_InvalidIDPSelection(t *testing.T) {
	_, server, mockProvider := setupSSOTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// First make a valid request to get cookie
	samlRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0" IssueInstant="2023-01-01T00:00:00Z">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded, err := encodeSAMLRequest(samlRequest)
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metadata/sso?SAMLRequest="+url.QueryEscape(encoded), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	cookies := resp.Cookies()
	resp.Body.Close()

	// Now try to select invalid IDP
	req2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/idp_selected?idp=invalid-idp", nil)
	require.NoError(t, err)

	for _, c := range cookies {
		req2.AddCookie(c)
	}

	client := &http.Client{}
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
}

func TestSSOEndpoint_IDPSelectionSuccess(t *testing.T) {
	_, server, mockProvider := setupSSOTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// First make a valid request
	samlRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0" IssueInstant="2023-01-01T00:00:00Z">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded, err := encodeSAMLRequest(samlRequest)
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metadata/sso?SAMLRequest="+url.QueryEscape(encoded)+"&RelayState=test-state", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	cookies := resp.Cookies()
	resp.Body.Close()

	// Select an IDP
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req3, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/idp_selected?idpID=test-idp", nil)
	require.NoError(t, err)

	for _, c := range cookies {
		req3.AddCookie(c)
	}

	resp2, err := client.Do(req3)
	require.NoError(t, err)
	defer resp2.Body.Close()

	// Should redirect to selected IDP
	assert.Equal(t, http.StatusFound, resp2.StatusCode)
	location := resp2.Header.Get("Location")
	assert.Contains(t, location, mockProvider.ssoURL)
	assert.Contains(t, location, "SAMLRequest=")
	assert.Contains(t, location, "RelayState=test-state")
}

func TestSSOEndpoint_HTTPPOSTBinding(t *testing.T) {
	t.Skip("HTTP POST binding for SSO is not supported by the underlying SAML library")

	// The test below documents the expected behavior if POST binding were supported.
	// Currently, the zitadel/saml library's HttpHandler returns 404 for POST requests to /sso.
	// Our handleSSO function correctly extracts SAML data from POST requests, but the
	// underlying library doesn't process them.

	cfg, server, mockProvider := setupSSOTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create SAML request for POST binding
	samlRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0" IssueInstant="2023-01-01T00:00:00Z">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	// Base64 encode without deflating (POST binding doesn't use deflate)
	encoded := base64.StdEncoding.EncodeToString([]byte(samlRequest))

	// Send as POST
	form := url.Values{}
	form.Set("SAMLRequest", encoded)
	form.Set("RelayState", "post-relay-state")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/metadata/sso", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should handle POST binding and show IDP selection page
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)

	// Verify response contains IDP selection page
	assert.Contains(t, bodyStr, "Select an Identity Provider")
	assert.Contains(t, bodyStr, cfg.IDP[0].ID)
	assert.Contains(t, bodyStr, cfg.IDP[1].ID)

	// Verify RelayState is preserved
	assert.Contains(t, bodyStr, "post-relay-state")

	// Verify auth request cookie is set
	cookies := resp.Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "authID" {
			authCookie = c

			break
		}
	}
	assert.NotNil(t, authCookie, "Should set auth request cookie")
	assert.NotEmpty(t, authCookie.Value)
}
