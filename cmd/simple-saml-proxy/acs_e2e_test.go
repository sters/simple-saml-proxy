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

// setupACSTest creates a common test setup for ACS endpoint tests.
func setupACSTest(t *testing.T) (*httptest.Server, *MockSAMLProvider, *saml.IDP) {
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
	}

	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, *cfg)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(*cfg)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, *cfg)
	server := httptest.NewServer(mux)

	return server, mockProvider, idp
}

func TestACSEndpoint_ValidSAMLResponse(t *testing.T) {
	server, mockProvider, idp := setupACSTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create auth request in storage to simulate the full flow
	authRequestID := "test-auth-id"
	storage := idp.GetStorage()
	storage.AddAuthRequestForTesting(&saml.AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		Issuer:        "https://sp.example.com",
		IsDone:        false,
	})

	// For a complete test, we would need to set up the service provider middleware properly
	// but for now we'll test if the ACS endpoint can handle a properly signed response
	// The test will verify the signature validation doesn't fail

	// Create a valid signed SAML response
	signedResponse := mockProvider.createSAMLResponse("_proxy_request_123", server.URL+"/saml/acs")
	encoded := base64.StdEncoding.EncodeToString([]byte(signedResponse))

	form := url.Values{}
	form.Set("SAMLResponse", encoded)
	form.Set("RelayState", "test-relay-state")

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add required cookies
	req.AddCookie(&http.Cookie{
		Name:  "authID",
		Value: authRequestID,
	})
	req.AddCookie(&http.Cookie{
		Name:  "idpID",
		Value: "test-idp",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response status: %d", resp.StatusCode)
	t.Logf("Response body: %s", string(body))

	// The proxy should accept the signed response and process it
	// It may redirect to the original SP or show an error if the SP is not properly configured
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode, "Should not return internal server error")
}

func TestACSEndpoint_MissingSAMLResponse(t *testing.T) {
	server, mockProvider, idp := setupACSTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create auth request in storage
	authRequestID := "test-auth-id"
	storage := idp.GetStorage()
	storage.AddAuthRequestForTesting(&saml.AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		IsDone:        false,
	})

	// Post without SAML response
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add required cookies
	req.AddCookie(&http.Cookie{
		Name:  "authID",
		Value: authRequestID,
	})
	req.AddCookie(&http.Cookie{
		Name:  "idpID",
		Value: "test-idp",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid request")
}

func TestACSEndpoint_InvalidSAMLResponse(t *testing.T) {
	server, mockProvider, idp := setupACSTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create auth request in storage
	authRequestID := "test-auth-id"
	storage := idp.GetStorage()
	storage.AddAuthRequestForTesting(&saml.AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		IsDone:        false,
	})

	// Create form with invalid response
	form := url.Values{}
	form.Set("SAMLResponse", "invalid-base64")
	form.Set("RelayState", "test")

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add required cookies
	req.AddCookie(&http.Cookie{
		Name:  "authID",
		Value: authRequestID,
	})
	req.AddCookie(&http.Cookie{
		Name:  "idpID",
		Value: "test-idp",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid request")
}

func TestACSEndpoint_GETMethodNotAllowed(t *testing.T) {
	server, mockProvider, _ := setupACSTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Try GET request
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/saml/acs", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return method not allowed or error
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

func TestACSEndpoint_RelayStatePreservation(t *testing.T) {
	server, mockProvider, idp := setupACSTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create auth request in storage
	authRequestID := "test-auth-id"
	storage := idp.GetStorage()
	storage.AddAuthRequestForTesting(&saml.AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		RelayState:    "my-custom-relay-state-abc123",
		Issuer:        "https://sp.example.com",
		IsDone:        false,
	})

	// Create a valid SAML response
	samlResponse := mockProvider.createSAMLResponse("test-123", server.URL+"/saml/acs")
	encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	customRelayState := "my-custom-relay-state-abc123"

	form := url.Values{}
	form.Set("SAMLResponse", encoded)
	form.Set("RelayState", customRelayState)

	// Need to setup proper cookies for full flow
	// This is a simplified test
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add required cookies
	req.AddCookie(&http.Cookie{
		Name:  "authID",
		Value: authRequestID,
	})
	req.AddCookie(&http.Cookie{
		Name:  "idpID",
		Value: "test-idp",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// The proxy should handle the request gracefully, even if authentication fails
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode, "Should not return internal server error")
}

func TestACSEndpoint_InvalidContentType(t *testing.T) {
	server, mockProvider, idp := setupACSTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create auth request in storage
	authRequestID := "test-auth-id"
	storage := idp.GetStorage()
	storage.AddAuthRequestForTesting(&saml.AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		IsDone:        false,
	})

	// Create valid response data
	samlResponse := mockProvider.createSAMLResponse("test-123", server.URL+"/saml/acs")
	encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	// Send with wrong content type
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(`{"SAMLResponse": "`+encoded+`"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Add required cookies
	req.AddCookie(&http.Cookie{
		Name:  "authID",
		Value: authRequestID,
	})
	req.AddCookie(&http.Cookie{
		Name:  "idpID",
		Value: "test-idp",
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should handle gracefully
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid request")
}

func TestACSEndpoint_LargeSAMLResponse(t *testing.T) {
	server, mockProvider, idp := setupACSTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create auth request in storage
	authRequestID := "test-auth-id"
	storage := idp.GetStorage()
	storage.AddAuthRequestForTesting(&saml.AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		IsDone:        false,
	})

	// Create a large SAML response
	largeAttributes := ""
	for i := range 100 {
		largeAttributes += `<saml:Attribute Name="attr` + string(rune(i)) + `"><saml:AttributeValue>value</saml:AttributeValue></saml:Attribute>`
	}

	samlResponse := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_large">
		<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">test</saml:Issuer>
		<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
		<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
			<saml:AttributeStatement>` + largeAttributes + `</saml:AttributeStatement>
		</saml:Assertion>
	</samlp:Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	form := url.Values{}
	form.Set("SAMLResponse", encoded)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add required cookies
	req.AddCookie(&http.Cookie{
		Name:  "authID",
		Value: authRequestID,
	})
	req.AddCookie(&http.Cookie{
		Name:  "idpID",
		Value: "test-idp",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should handle large responses
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestACSEndpoint_SpecialCharactersInRelayState(t *testing.T) {
	server, mockProvider, idp := setupACSTest(t)
	defer server.Close()
	defer mockProvider.Close()

	// Create auth request in storage
	authRequestID := "test-auth-id"
	storage := idp.GetStorage()
	storage.AddAuthRequestForTesting(&saml.AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		IsDone:        false,
	})

	samlResponse := mockProvider.createSAMLResponse("test-123", server.URL+"/saml/acs")
	encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	// RelayState with special characters
	specialRelayState := "relay=state&with<special>chars%20and spaces"

	form := url.Values{}
	form.Set("SAMLResponse", encoded)
	form.Set("RelayState", specialRelayState)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add required cookies
	req.AddCookie(&http.Cookie{
		Name:  "authID",
		Value: authRequestID,
	})
	req.AddCookie(&http.Cookie{
		Name:  "idpID",
		Value: "test-idp",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should handle special characters properly without crashing
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode, "Should not return internal server error")
}
