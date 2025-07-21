package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogoutResponseHandling tests the handling of logout responses.
func TestLogoutResponseHandling(t *testing.T) {
	t.Log("Starting logout response handling test...")

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

	t.Run("SPInitiatedLogoutResponse", func(t *testing.T) {
		// First, create a logout context in storage (simulating a previous logout request)
		storage := idp.GetStorage()
		logoutCtx := storage.CreateLogoutContext("sp", "https://sp.example.com", "mock-idp", "test_relay")

		// Create a logout response from IdP
		logoutResponse := &crewjamsaml.LogoutResponse{
			ID:           "resp_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now(),
			Issuer: &crewjamsaml.Issuer{
				Value: mockIdp.server.URL + "/saml/metadata",
			},
			Status: crewjamsaml.Status{
				StatusCode: crewjamsaml.StatusCode{
					Value: crewjamsaml.StatusSuccess,
				},
			},
		}

		// Encode the logout response
		encoded := encodeLogoutResponse(t, logoutResponse)

		// Create request with logout context cookie
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/slo/response?SAMLResponse="+encoded+"&RelayState=test_relay", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{
			Name:  "logout_context_id",
			Value: logoutCtx.ID,
		})

		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect back to SP with logout response
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		location := resp.Header.Get("Location")
		assert.Contains(t, location, "https://sp.example.com/logout/response")
		assert.Contains(t, location, "SAMLResponse=")
		assert.Contains(t, location, "RelayState=test_relay")

		// Verify logout context was cleaned up
		_, err = storage.GetLogoutContext(logoutCtx.ID)
		assert.Error(t, err, "Logout context should be deleted after completion")
	})

	t.Run("IdPInitiatedLogoutResponseFromSP", func(t *testing.T) {
		// Create a logout context for IdP-initiated flow
		storage := idp.GetStorage()
		logoutCtx := storage.CreateLogoutContext("idp", mockIdp.server.URL+"/saml/metadata", "https://sp.example.com", "idp_relay")

		// Create a logout response from SP
		logoutResponse := &crewjamsaml.LogoutResponse{
			ID:           "sp_resp_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now(),
			Issuer: &crewjamsaml.Issuer{
				Value: "https://sp.example.com",
			},
			Status: crewjamsaml.Status{
				StatusCode: crewjamsaml.StatusCode{
					Value: crewjamsaml.StatusSuccess,
				},
			},
		}

		// Encode the logout response
		encoded := encodeLogoutResponse(t, logoutResponse)

		// Create request with logout context cookie
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/slo/response?SAMLResponse="+encoded, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{
			Name:  "logout_context_id",
			Value: logoutCtx.ID,
		})

		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect back to IdP with logout response
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		location := resp.Header.Get("Location")
		assert.Contains(t, location, mockIdp.server.URL+"/saml/metadata/slo/response")
		assert.Contains(t, location, "SAMLResponse=")
		assert.Contains(t, location, "RelayState=idp_relay")
	})

	t.Run("LogoutResponseValidation", func(t *testing.T) {
		// Test with old logout response
		storage := idp.GetStorage()
		logoutCtx := storage.CreateLogoutContext("sp", "https://sp.example.com", "mock-idp", "")

		oldResponse := &crewjamsaml.LogoutResponse{
			ID:           "old_resp_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now().Add(-10 * time.Minute), // Too old
			Issuer: &crewjamsaml.Issuer{
				Value: mockIdp.server.URL + "/saml/metadata",
			},
			Status: crewjamsaml.Status{
				StatusCode: crewjamsaml.StatusCode{
					Value: crewjamsaml.StatusSuccess,
				},
			},
		}

		encoded := encodeLogoutResponse(t, oldResponse)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/sls?SAMLResponse="+encoded, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{
			Name:  "logout_context_id",
			Value: logoutCtx.ID,
		})

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("PartialLogoutStatus", func(t *testing.T) {
		// Test handling of partial logout status
		storage := idp.GetStorage()
		logoutCtx := storage.CreateLogoutContext("sp", "https://sp.example.com", "mock-idp", "")

		partialResponse := &crewjamsaml.LogoutResponse{
			ID:           "partial_" + generateLogoutID(),
			Version:      "2.0",
			IssueInstant: time.Now(),
			Issuer: &crewjamsaml.Issuer{
				Value: mockIdp.server.URL + "/saml/metadata",
			},
			Status: crewjamsaml.Status{
				StatusCode: crewjamsaml.StatusCode{
					Value: crewjamsaml.StatusResponder,
					StatusCode: &crewjamsaml.StatusCode{
						Value: crewjamsaml.StatusPartialLogout,
					},
				},
			},
		}

		encoded := encodeLogoutResponse(t, partialResponse)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/sls?SAMLResponse="+encoded, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{
			Name:  "logout_context_id",
			Value: logoutCtx.ID,
		})

		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should still redirect but with partial logout status
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		location := resp.Header.Get("Location")
		assert.Contains(t, location, "SAMLResponse=")

		// Decode and verify the response contains partial logout status
		u, err := url.Parse(location)
		require.NoError(t, err)
		responseParam := u.Query().Get("SAMLResponse")
		decodedResp, err := parseLogoutResponse(responseParam)
		require.NoError(t, err)
		assert.Equal(t, crewjamsaml.StatusResponder, decodedResp.Status.StatusCode.Value)
	})
}

// Helper function to encode a logout response for HTTP-Redirect binding.
func encodeLogoutResponse(t *testing.T, response *crewjamsaml.LogoutResponse) string {
	t.Helper()
	// Marshal to XML
	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	xmlBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	// Compress using deflate
	compressed, err := deflateCompress(xmlBytes)
	require.NoError(t, err)

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(compressed)

	return url.QueryEscape(encoded)
}
