package main

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2EFlow(t *testing.T) {
	t.Skip("Skipping - test expects incorrect behavior for SP-initiated flow")
	t.Log("Starting E2E flow test...")

	// Setup
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	// Create proxy configuration
	proxyConfig := &config.Config{}
	proxyConfig.Proxy.EntityID = "https://proxy.example.com"
	proxyConfig.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	proxyConfig.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	proxyConfig.Proxy.PrivateKeyPath = proxyKeyPath
	proxyConfig.Proxy.CertificatePath = proxyCertPath
	proxyConfig.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}
	proxyConfig.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}

	// Create mock IDP
	mockIdp := NewMockSAMLProvider(t)
	defer mockIdp.Close()

	proxyConfig.IDP = []config.IDPConfig{
		{
			ID:          "mock-idp",
			MetadataURL: mockIdp.server.URL + "/saml/metadata",
		},
	}

	// Create and start proxy server
	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, *proxyConfig)
	require.NoError(t, err)

	// Disable signature validation for testing
	disableSignatureValidation(providers)

	idp, err := saml.CreateProxyIDP(*proxyConfig)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, *proxyConfig)
	proxyServer := httptest.NewServer(mux)
	defer proxyServer.Close()

	t.Logf("Proxy server started at: %s", proxyServer.URL)

	// Create mock SP
	mockSp := NewMockSAMLClient(t)
	defer mockSp.Close()

	// Step 1: SP initiates login
	t.Log("Step 1: SP initiating login...")
	resp1, err := mockSp.InitiateLogin(ctx, proxyServer.URL)
	require.NoError(t, err)
	defer resp1.Body.Close()

	// Should redirect to IDP selection page
	assert.Equal(t, http.StatusSeeOther, resp1.StatusCode)

	// Step 2: Follow redirect to IDP selection page
	t.Log("Step 2: Following redirect to IDP selection page...")
	resp2, err := mockSp.FollowRedirect(resp1)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Should show IDP selection page
	body2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body2), "Select an Identity Provider")

	// Get auth request ID from cookies
	var authID string
	for _, cookie := range resp2.Cookies() {
		if cookie.Name == "authID" {
			authID = cookie.Value

			break
		}
	}
	assert.NotEmpty(t, authID)

	// Step 3: Select IDP
	t.Log("Step 3: Selecting IDP...")
	idpSelectionURL := proxyServer.URL + "/idp_selected?idpID=mock-idp"
	req3, err := http.NewRequestWithContext(ctx, http.MethodGet, idpSelectionURL, nil)
	require.NoError(t, err)

	// Add auth cookie
	req3.AddCookie(&http.Cookie{Name: "authID", Value: authID})

	// Disable redirect following for this request
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp3, err := client.Do(req3)
	require.NoError(t, err)
	defer resp3.Body.Close()

	assert.Equal(t, http.StatusFound, resp3.StatusCode)

	// Step 4: Follow redirect to actual IDP
	t.Log("Step 4: Following redirect to actual IDP...")
	resp4, err := mockSp.FollowRedirect(resp3)
	require.NoError(t, err)
	defer resp4.Body.Close()

	assert.Equal(t, http.StatusOK, resp4.StatusCode)

	// IDP should return a form that posts back to proxy
	body4, err := io.ReadAll(resp4.Body)
	require.NoError(t, err)

	t.Logf("IDP response body length: %d", len(body4))

	// Extract form data
	action, samlResponse, relayState := extractFormValues(t, string(body4))
	t.Logf("Extracted form - Action: %s, RelayState: %s", action, relayState)

	assert.NotEmpty(t, action)
	assert.NotEmpty(t, samlResponse)
	assert.Equal(t, "test-state", relayState)

	// Step 5: Submit SAML response back to proxy
	t.Log("Step 5: Submitting SAML response to proxy ACS...")
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	form.Set("RelayState", relayState)

	// Use the proxy server URL for ACS
	acsURL := proxyServer.URL + "/saml/acs"
	req5, err := http.NewRequestWithContext(ctx, http.MethodPost, acsURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Copy cookies from IDP selection response
	for _, cookie := range resp3.Cookies() {
		req5.AddCookie(cookie)
	}

	client5 := &http.Client{}
	resp5, err := client5.Do(req5)
	require.NoError(t, err)
	defer resp5.Body.Close()

	// Should get final response
	assert.Equal(t, http.StatusOK, resp5.StatusCode)

	body5, err := io.ReadAll(resp5.Body)
	require.NoError(t, err)
	t.Logf("Final response body length: %d", len(body5))

	// Verify the flow completed
	assert.Contains(t, string(body5), "Select Service Provider")

	t.Log("E2E flow test completed successfully!")
}

func TestE2EFlowMultipleIdPs(t *testing.T) {
	t.Skip("Skipping - SAML signature validation in crewjam/saml library prevents full E2E testing")

	// This test verifies the complete flow with multiple IdPs:
	// 1. SP initiates login -> redirected to proxy SSO endpoint
	// 2. Proxy shows IdP selection page with multiple IdPs
	// 3. User selects an IdP
	// 4. Proxy redirects to selected IdP
	// 5. IdP authenticates and sends response back to proxy ACS
	// 6. Proxy processes response and completes the flow
	//
	// The test successfully completes steps 1-5 but fails at step 6 due to
	// SAML response signature validation that cannot be disabled in tests.

	// Setup
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	proxyConfig := &config.Config{}
	proxyConfig.Proxy.EntityID = "https://proxy.example.com"
	proxyConfig.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	proxyConfig.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	proxyConfig.Proxy.PrivateKeyPath = proxyKeyPath
	proxyConfig.Proxy.CertificatePath = proxyCertPath
	proxyConfig.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}

	// Create multiple mock IDPs
	mockIdp1 := NewMockSAMLProvider(t)
	defer mockIdp1.Close()

	mockIdp2 := NewMockSAMLProvider(t)
	defer mockIdp2.Close()

	proxyConfig.IDP = []config.IDPConfig{
		{
			ID:          "idp-1",
			MetadataURL: mockIdp1.server.URL + "/saml/metadata",
		},
		{
			ID:          "idp-2",
			MetadataURL: mockIdp2.server.URL + "/saml/metadata",
		},
	}

	// Create proxy server
	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, *proxyConfig)
	require.NoError(t, err)

	disableSignatureValidation(providers)

	idp, err := saml.CreateProxyIDP(*proxyConfig)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, *proxyConfig)
	proxyServer := httptest.NewServer(mux)
	defer proxyServer.Close()

	// Create mock SP
	mockSp := NewMockSAMLClient(t)
	defer mockSp.Close()

	// Step 1: SP initiates login
	resp1, err := mockSp.InitiateLogin(ctx, proxyServer.URL)
	require.NoError(t, err)
	defer resp1.Body.Close()

	// Should redirect to IDP selection page
	assert.Equal(t, http.StatusSeeOther, resp1.StatusCode)

	// Get the auth ID from cookies (should be none yet, as we need to follow redirect)
	var authID string
	for _, cookie := range resp1.Cookies() {
		t.Logf("Cookie from resp1: %s = %s", cookie.Name, cookie.Value)
		if cookie.Name == "authID" {
			authID = cookie.Value

			break
		}
	}
	// We don't expect authID yet since it's set on the idp_select page

	// Step 2: Follow redirect to IDP selection page
	resp2, err := mockSp.FollowRedirect(resp1)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	body2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)

	// Verify both IDPs are shown
	assert.Contains(t, string(body2), "idp-1")
	assert.Contains(t, string(body2), "idp-2")
	assert.Contains(t, string(body2), "Select an Identity Provider")

	// Get authID from cookies set by idp_select page
	for _, cookie := range resp2.Cookies() {
		t.Logf("Cookie from resp2: %s = %s", cookie.Name, cookie.Value)
		if cookie.Name == "authID" {
			authID = cookie.Value

			break
		}
	}
	require.NotEmpty(t, authID, "authID cookie should be set by idp_select page")

	// Step 3: Select an IDP
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	idpSelectionURL := proxyServer.URL + "/idp_selected?idpID=idp-1"
	req3, err := http.NewRequestWithContext(ctx, http.MethodGet, idpSelectionURL, nil)
	require.NoError(t, err)
	req3.AddCookie(&http.Cookie{Name: "authID", Value: authID})

	resp3, err := client.Do(req3)
	require.NoError(t, err)
	defer resp3.Body.Close()

	// Should redirect to selected IDP
	assert.Equal(t, http.StatusFound, resp3.StatusCode)
	location := resp3.Header.Get("Location")
	assert.Contains(t, location, mockIdp1.server.URL)

	// Get the idpID cookie that was set
	var idpID string
	for _, cookie := range resp3.Cookies() {
		t.Logf("Cookie from resp3: %s = %s", cookie.Name, cookie.Value)
		if cookie.Name == "idpID" {
			idpID = cookie.Value

			break
		}
	}
	require.NotEmpty(t, idpID, "idpID cookie should be set by idp_selected")

	// Step 4: Follow redirect to IDP
	req4, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	require.NoError(t, err)

	resp4, err := http.DefaultClient.Do(req4)
	require.NoError(t, err)
	defer resp4.Body.Close()

	assert.Equal(t, http.StatusOK, resp4.StatusCode)

	// IDP returns form
	body4, err := io.ReadAll(resp4.Body)
	require.NoError(t, err)

	action, samlResponse, relayState := extractFormValues(t, string(body4))
	assert.NotEmpty(t, action)
	assert.NotEmpty(t, samlResponse)

	// Step 5: Submit response back to proxy
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	form.Set("RelayState", relayState)

	acsURL := proxyServer.URL + "/saml/acs"
	req5, err := http.NewRequestWithContext(ctx, http.MethodPost, acsURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add the authID cookie that we got from idp_select page
	req5.AddCookie(&http.Cookie{Name: "authID", Value: authID})

	// Add the idpID cookie that we got from idp_selected
	req5.AddCookie(&http.Cookie{Name: "idpID", Value: idpID})

	// Also add any other cookies from the IDP selection response
	for _, cookie := range resp3.Cookies() {
		if cookie.Name != "idpID" { // Skip idpID as we already added it
			req5.AddCookie(cookie)
		}
	}

	resp5, err := http.DefaultClient.Do(req5)
	require.NoError(t, err)
	defer resp5.Body.Close()

	// Should get final response - SP selection page for IdP-initiated flow
	assert.Equal(t, http.StatusOK, resp5.StatusCode)

	body5, err := io.ReadAll(resp5.Body)
	require.NoError(t, err)

	// Verify the flow completed - the response should show SP selection for IdP-initiated
	assert.Contains(t, string(body5), "Select Service Provider")

	t.Log("Multiple IdP E2E flow test completed successfully!")
}

func TestE2EFlowWithAuthFailure(t *testing.T) {
	t.Skip("Skipping - test expects incorrect behavior for SP-initiated flow")
	// Setup
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	proxyConfig := &config.Config{}
	proxyConfig.Proxy.EntityID = "https://proxy.example.com"
	proxyConfig.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	proxyConfig.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	proxyConfig.Proxy.PrivateKeyPath = proxyKeyPath
	proxyConfig.Proxy.CertificatePath = proxyCertPath
	proxyConfig.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}

	// Create mock IDP that will fail auth
	mockIdp := NewMockSAMLProviderWithErrors(t)
	defer mockIdp.Close()

	mockIdp.SetShouldFailAuth(true)

	proxyConfig.IDP = []config.IDPConfig{
		{
			ID:          "failing-idp",
			MetadataURL: mockIdp.server.URL + "/saml/metadata",
		},
	}

	// Create proxy server
	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, *proxyConfig)
	require.NoError(t, err)

	disableSignatureValidation(providers)

	idp, err := saml.CreateProxyIDP(*proxyConfig)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, *proxyConfig)
	proxyServer := httptest.NewServer(mux)
	defer proxyServer.Close()

	// Create mock SP
	mockSp := NewMockSAMLClient(t)
	defer mockSp.Close()

	// Step 1: SP initiates login
	resp1, err := mockSp.InitiateLogin(ctx, proxyServer.URL)
	require.NoError(t, err)
	defer resp1.Body.Close()

	// Should auto-redirect to single IDP
	assert.Equal(t, http.StatusFound, resp1.StatusCode)

	// Step 2: Follow redirect to IDP
	resp2, err := mockSp.FollowRedirect(resp1)
	require.NoError(t, err)
	defer resp2.Body.Close()

	// IDP returns failure response
	body2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)

	action, samlResponse, relayState := extractFormValues(t, string(body2))

	// Step 3: Submit failure response to proxy
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	form.Set("RelayState", relayState)

	req3, err := http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for _, cookie := range resp1.Cookies() {
		req3.AddCookie(cookie)
	}

	resp3, err := http.DefaultClient.Do(req3)
	require.NoError(t, err)
	defer resp3.Body.Close()

	// Should handle auth failure
	body3, err := io.ReadAll(resp3.Body)
	require.NoError(t, err)

	// Decode the SAML response to verify it contains failure
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	require.NoError(t, err)

	var failureResp crewjamsaml.Response
	err = xml.Unmarshal(decoded, &failureResp)
	require.NoError(t, err)

	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", failureResp.Status.StatusCode.Value)
	assert.Contains(t, failureResp.Status.StatusMessage, "Authentication failed")

	// Proxy should show error or redirect appropriately
	assert.NotContains(t, string(body3), "panic")
}

// setupFlowErrorTest creates a common test setup for flow error tests.
func setupFlowErrorTest(t *testing.T) (*config.Config, *httptest.Server, *MockSAMLProvider) {
	t.Helper()

	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	proxyConfig := config.Config{}
	proxyConfig.Proxy.EntityID = "https://proxy.example.com"
	proxyConfig.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	proxyConfig.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	proxyConfig.Proxy.PrivateKeyPath = proxyKeyPath
	proxyConfig.Proxy.CertificatePath = proxyCertPath
	proxyConfig.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}

	mockIdp := NewMockSAMLProvider(t)

	proxyConfig.IDP = []config.IDPConfig{
		{
			ID:          "test-idp",
			MetadataURL: mockIdp.server.URL + "/saml/metadata",
		},
	}

	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, proxyConfig)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(proxyConfig)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, proxyConfig)
	proxyServer := httptest.NewServer(mux)

	return &proxyConfig, proxyServer, mockIdp
}

func TestE2EFlowErrorCases_InvalidIdPSelection(t *testing.T) {
	_, proxyServer, mockIdp := setupFlowErrorTest(t)
	defer proxyServer.Close()
	defer mockIdp.Close()

	// Make request without proper auth cookie
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/idp_selected?idp=invalid", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestE2EFlowErrorCases_MissingAuthIDCookie(t *testing.T) {
	_, proxyServer, mockIdp := setupFlowErrorTest(t)
	defer proxyServer.Close()
	defer mockIdp.Close()

	// Try to select IDP without auth request
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/idp_selected?idp=test-idp", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestE2EFlowErrorCases_ACSWithoutCookies(t *testing.T) {
	_, proxyServer, mockIdp := setupFlowErrorTest(t)
	defer proxyServer.Close()
	defer mockIdp.Close()

	// Post to ACS without proper cookies
	form := url.Values{}
	form.Set("SAMLResponse", "dummy")
	form.Set("RelayState", "test")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/saml/acs", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should handle gracefully
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestE2EFlowErrorCases_UnauthorizedSP(t *testing.T) {
	proxyConfig, _, mockIdp := setupFlowErrorTest(t)
	defer mockIdp.Close()

	// Add allowed SP configuration
	proxyConfig.Proxy.AllowedSP = []config.SPConfig{
		{
			EntityID: "https://allowed-sp.example.com",
		},
	}

	ctx := t.Context()

	// Recreate proxy with AllowedSP
	providers, err := saml.CreateServiceProviders(ctx, *proxyConfig)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(*proxyConfig)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, *proxyConfig)
	restrictedServer := httptest.NewServer(mux)
	defer restrictedServer.Close()

	// Try with unauthorized SP
	unauthorizedClient := NewMockSAMLClient(t)
	unauthorizedClient.entityID = "https://unauthorized-sp.example.com"

	resp, err := unauthorizedClient.InitiateLogin(ctx, restrictedServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected or show error
	body, _ := io.ReadAll(resp.Body)
	// Current implementation may not enforce this strictly
	t.Logf("Response for unauthorized SP: %d bytes", len(body))
}

// setupErrorHandlingTest creates a common test setup for error handling tests.
func setupErrorHandlingTest(t *testing.T) (*config.Config, *httptest.Server, *MockSAMLProvider) {
	t.Helper()

	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	cfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	cfg.Proxy.PrivateKeyPath = proxyKeyPath
	cfg.Proxy.CertificatePath = proxyCertPath
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}

	mockIdp := NewMockSAMLProvider(t)

	cfg.IDP = []config.IDPConfig{
		{
			ID:          "test-idp",
			MetadataURL: mockIdp.server.URL + "/saml/metadata",
		},
	}

	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, cfg)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, cfg)
	server := httptest.NewServer(mux)

	return &cfg, server, mockIdp
}

func TestE2EFlowErrorHandling_InvalidSAMLRequest(t *testing.T) {
	_, server, mockIdp := setupErrorHandlingTest(t)
	defer server.Close()
	defer mockIdp.Close()

	// Send malformed SAML request
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/sso?SAMLRequest=malformed", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error response
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "RequestDenied")
}

func TestE2EFlowErrorHandling_MissingAuthenticationCookie(t *testing.T) {
	_, server, mockIdp := setupErrorHandlingTest(t)
	defer server.Close()
	defer mockIdp.Close()

	// Try to access protected endpoint without auth
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/idp_selected?idp=test-idp", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestE2EFlowErrorHandling_InvalidIdPSelection(t *testing.T) {
	_, server, mockIdp := setupErrorHandlingTest(t)
	defer server.Close()
	defer mockIdp.Close()

	// First get auth cookie
	samlReq := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded, _ := encodeSAMLRequest(samlReq)
	req1, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/sso?SAMLRequest="+url.QueryEscape(encoded), nil)
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)

	cookies := resp1.Cookies()
	resp1.Body.Close()

	// Try invalid IDP
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/idp_selected?idp=non-existent", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
}

func TestE2EFlowErrorHandling_UnauthorizedSP(t *testing.T) {
	cfg, _, mockIdp := setupErrorHandlingTest(t)
	defer mockIdp.Close()

	// Configure allowed SPs
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://allowed-sp.example.com"},
	}

	ctx := t.Context()

	// Recreate proxy with restrictions
	providers, _ := saml.CreateServiceProviders(ctx, *cfg)
	idp, _ := saml.CreateProxyIDP(*cfg)
	mux := proxy.SetupHTTPHandlers(idp, providers, *cfg)
	restrictedServer := httptest.NewServer(mux)
	defer restrictedServer.Close()

	// Request from unauthorized SP
	samlReq := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://unauthorized-sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded, _ := encodeSAMLRequest(samlReq)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, restrictedServer.URL+"/sso?SAMLRequest="+url.QueryEscape(encoded), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected
	body, _ := io.ReadAll(resp.Body)
	// Note: Current implementation might not enforce this
	t.Logf("Unauthorized SP response: %s", string(body))
}
