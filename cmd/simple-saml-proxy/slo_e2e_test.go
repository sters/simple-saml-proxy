package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateLogoutID generates a unique ID for logout requests/responses.
func generateLogoutID() string {
	return "_" + uuid.New().String()
}

// TestSPInitiatedLogoutFlow tests the complete SP-initiated logout flow.
func TestSPInitiatedLogoutFlow(t *testing.T) {
	t.Log("Starting SP-initiated logout flow test...")

	// Setup proxy
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)
	proxyConfig := &config.Config{}
	proxyConfig.Proxy.EntityID = "https://proxy.example.com"
	proxyConfig.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	proxyConfig.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	proxyConfig.Proxy.SLOURL = "https://proxy.example.com/slo"
	proxyConfig.Proxy.SLSURL = "https://proxy.example.com/sls"
	proxyConfig.Proxy.PrivateKeyPath = proxyKeyPath
	proxyConfig.Proxy.CertificatePath = proxyCertPath
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

	// Start proxy server
	ctx := t.Context()
	serviceProviders, err := saml.CreateServiceProviders(ctx, *proxyConfig)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(*proxyConfig)
	require.NoError(t, err)

	handler := proxy.SetupHTTPHandlers(idp, serviceProviders, *proxyConfig)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	var logoutContextID string
	t.Run("Step1_SPSendsLogoutRequest", func(t *testing.T) {
		// Create a logout request from SP
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           "logout_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now(),
			Issuer: &crewjamsaml.Issuer{
				Value: "https://sp.example.com",
			},
			NameID: &crewjamsaml.NameID{
				Value:  "user@example.com",
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
			},
			SessionIndex: &crewjamsaml.SessionIndex{
				Value: "session_123",
			},
		}

		// Encode the logout request
		encoded := encodeLogoutRequest(t, logoutRequest)

		// Send logout request to proxy
		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/slo?SAMLRequest="+url.QueryEscape(encoded)+"&RelayState=test_relay", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect to IdP selection page
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		location, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, "/logout_idp_select", location.Path)

		// Check that logout context cookie was set
		cookies := resp.Cookies()
		var logoutCtxCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "logout_context_id" {
				logoutCtxCookie = cookie

				break
			}
		}
		require.NotNil(t, logoutCtxCookie, "logout_context_id cookie should be set")
		logoutContextID = logoutCtxCookie.Value // Store for next step
	})

	t.Run("Step2_UserSelectsIdPAndProxyRelaysLogout", func(t *testing.T) {
		// Skip if we don't have a logout context ID from Step1
		if logoutContextID == "" {
			t.Skip("No logout context ID from Step1")
		}

		// Simulate user selecting an IdP
		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}

		// First get the IdP selection page to get the logout context
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/logout_idp_select", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "logout_context_id", Value: logoutContextID})

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Submit IdP selection
		formData := url.Values{
			"idpID": {"mock-idp"},
		}
		req, err = http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/logout_idp_selected", strings.NewReader(formData.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "logout_context_id", Value: logoutContextID})

		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect to upstream IdP with logout request
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		location := resp.Header.Get("Location")
		assert.Contains(t, location, "/saml/slo") // Mock IdP's SLO endpoint
		assert.Contains(t, location, "SAMLRequest=")
	})
}

// TestIdPInitiatedLogoutFlow tests the complete IdP-initiated logout flow.
func TestIdPInitiatedLogoutFlow(t *testing.T) {
	t.Log("Starting IdP-initiated logout flow test...")

	// Setup proxy
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)
	proxyConfig := &config.Config{}
	proxyConfig.Proxy.EntityID = "https://proxy.example.com"
	proxyConfig.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	proxyConfig.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	proxyConfig.Proxy.SLOURL = "https://proxy.example.com/slo"
	proxyConfig.Proxy.SLSURL = "https://proxy.example.com/sls"
	proxyConfig.Proxy.PrivateKeyPath = proxyKeyPath
	proxyConfig.Proxy.CertificatePath = proxyCertPath
	proxyConfig.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp1.example.com"},
		{EntityID: "https://sp2.example.com"},
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

	// Start proxy server
	ctx := t.Context()
	serviceProviders, err := saml.CreateServiceProviders(ctx, *proxyConfig)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(*proxyConfig)
	require.NoError(t, err)

	handler := proxy.SetupHTTPHandlers(idp, serviceProviders, *proxyConfig)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	var idpLogoutContextID string
	t.Run("Step1_IdPSendsLogoutRequest", func(t *testing.T) {
		// Create a logout request from IdP (use the EntityID from metadata)
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           "idp_logout_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now(),
			Issuer: &crewjamsaml.Issuer{
				Value: "https://mockidp.example.com/saml/metadata", // Use the EntityID from metadata
			},
			NameID: &crewjamsaml.NameID{
				Value:  "user@example.com",
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
			},
		}

		// Encode the logout request
		encoded := encodeLogoutRequest(t, logoutRequest)

		// Send logout request from IdP to proxy
		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/sls?SAMLRequest="+url.QueryEscape(encoded)+"&RelayState=idp_relay", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect to SP selection page
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		location, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, "/logout_sp_select", location.Path)

		// Check that logout context cookie was set
		cookies := resp.Cookies()
		var logoutCtxCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "logout_context_id" {
				logoutCtxCookie = cookie

				break
			}
		}
		require.NotNil(t, logoutCtxCookie, "logout_context_id cookie should be set")
		idpLogoutContextID = logoutCtxCookie.Value // Store for next step
	})

	t.Run("Step2_UserSelectsSPAndProxyForwardsLogout", func(t *testing.T) {
		// Skip if we don't have a logout context ID from Step1
		if idpLogoutContextID == "" {
			t.Skip("No logout context ID from Step1")
		}

		// Simulate user selecting an SP
		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}

		// Submit SP selection
		formData := url.Values{
			"spEntityID": {"https://sp1.example.com"},
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/logout_sp_selected", strings.NewReader(formData.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "logout_context_id", Value: idpLogoutContextID})
		req.AddCookie(&http.Cookie{Name: "logout_name_id", Value: "user@example.com"})

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect to SP with logout request
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		location := resp.Header.Get("Location")
		assert.Contains(t, location, "https://sp1.example.com/logout")
		assert.Contains(t, location, "SAMLRequest=")
	})
}

// TestLogoutRequestValidation tests security validations for logout requests.
func TestLogoutRequestValidation(t *testing.T) {
	// Setup proxy
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)
	proxyConfig := &config.Config{}
	proxyConfig.Proxy.EntityID = "https://proxy.example.com"
	proxyConfig.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	proxyConfig.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	proxyConfig.Proxy.SLOURL = "https://proxy.example.com/slo"
	proxyConfig.Proxy.SLSURL = "https://proxy.example.com/sls"
	proxyConfig.Proxy.PrivateKeyPath = proxyKeyPath
	proxyConfig.Proxy.CertificatePath = proxyCertPath
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

	// Start proxy server
	ctx := t.Context()
	serviceProviders, err := saml.CreateServiceProviders(ctx, *proxyConfig)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(*proxyConfig)
	require.NoError(t, err)

	handler := proxy.SetupHTTPHandlers(idp, serviceProviders, *proxyConfig)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	t.Run("RejectUnauthorizedSP", func(t *testing.T) {
		// Create a logout request from unauthorized SP
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           "logout_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now(),
			Issuer: &crewjamsaml.Issuer{
				Value: "https://unauthorized.example.com",
			},
			NameID: &crewjamsaml.NameID{
				Value: "user@example.com",
			},
		}

		encoded := encodeLogoutRequest(t, logoutRequest)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/slo?SAMLRequest="+url.QueryEscape(encoded), nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("RejectOldLogoutRequest", func(t *testing.T) {
		// Create an old logout request
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           "logout_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now().Add(-10 * time.Minute), // Too old
			Issuer: &crewjamsaml.Issuer{
				Value: "https://sp.example.com",
			},
			NameID: &crewjamsaml.NameID{
				Value: "user@example.com",
			},
		}

		encoded := encodeLogoutRequest(t, logoutRequest)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/slo?SAMLRequest="+url.QueryEscape(encoded), nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("RejectFutureLogoutRequest", func(t *testing.T) {
		// Create a future logout request
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           "logout_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now().Add(10 * time.Minute), // In the future
			Issuer: &crewjamsaml.Issuer{
				Value: "https://sp.example.com",
			},
			NameID: &crewjamsaml.NameID{
				Value: "user@example.com",
			},
		}

		encoded := encodeLogoutRequest(t, logoutRequest)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/slo?SAMLRequest="+url.QueryEscape(encoded), nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// Helper function to encode a logout request for HTTP-Redirect binding.
func encodeLogoutRequest(t *testing.T, request *crewjamsaml.LogoutRequest) string {
	t.Helper()
	// Marshal to XML
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	xmlBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	// Compress using deflate
	compressed, err := deflateCompress(xmlBytes)
	require.NoError(t, err)

	// Base64 encode (don't URL escape here, let the caller do it)
	encoded := base64.StdEncoding.EncodeToString(compressed)

	return encoded
}

// Helper function to compress data using deflate.
func deflateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to create flate writer: %w", err)
	}
	_, err = w.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}
	err = w.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close flate writer: %w", err)
	}

	return buf.Bytes(), nil
}

// Helper function to parse logout response.
func parseLogoutResponse(responseStr string) (*crewjamsaml.LogoutResponse, error) {
	// Base64 decode (no URL decoding needed as Go's query parsing already did it)
	compressed, err := base64.StdEncoding.DecodeString(responseStr)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode: %w", err)
	}

	// Try to decompress using flate
	reader := flate.NewReader(strings.NewReader(string(compressed)))
	decompressed, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		// Try without decompression
		decompressed = compressed
	}

	// Parse XML
	var response crewjamsaml.LogoutResponse
	err = xml.Unmarshal(decompressed, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	return &response, nil
}
