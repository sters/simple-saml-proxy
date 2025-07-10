package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy"
	proxySAML "github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAssertionDataPassThrough tests that user attributes from the IdP are correctly passed to the SP.
func TestAssertionDataPassThrough(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := generateTestCertificate(t)

	// Create mock IdP with custom user attributes
	mockIDP := NewMockSAMLProvider(t)
	defer mockIDP.Close()

	// Set custom user attributes
	customAttrs := map[string]string{
		"nameID":    "john.doe@company.com",
		"email":     "john.doe@company.com",
		"name":      "John Doe",
		"givenName": "John",
		"surname":   "Doe",
	}
	mockIDP.SetUserAttributes(customAttrs)

	// Set up environment
	envVars := map[string]string{
		"PROXY_ENTITY_ID":              "http://localhost:8080",
		"PROXY_ACS_URL":                "http://localhost:8080/saml/acs",
		"PROXY_METADATA_URL":           "http://localhost:8080/metadata",
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

	// Create a mock SP client
	mockClient := NewMockSAMLClient(t)
	defer mockClient.Close()

	// Step 1: Initiate login from SP
	resp, err := mockClient.InitiateLogin(t.Context(), proxyServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should redirect to IdP selection
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	location := resp.Header.Get("Location")
	require.Contains(t, location, "/idp_select")

	// Step 2: Follow redirect to IdP selection page
	cookies := resp.Cookies()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+location, nil)
	require.NoError(t, err)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp2, err := client.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()
	cookies = append(cookies, resp2.Cookies()...)

	// Step 3: Select the IdP
	selectURL := proxyServer.URL + "/idp_selected?idpID=test-idp"
	req3, err := http.NewRequestWithContext(t.Context(), http.MethodGet, selectURL, nil)
	require.NoError(t, err)
	for _, cookie := range cookies {
		req3.AddCookie(cookie)
	}

	resp3, err := client.Do(req3)
	require.NoError(t, err)
	defer resp3.Body.Close()
	cookies = append(cookies, resp3.Cookies()...)

	// Should redirect to mock IdP
	require.Equal(t, http.StatusFound, resp3.StatusCode)
	idpLocation := resp3.Header.Get("Location")
	require.Contains(t, idpLocation, mockIDP.server.URL)

	// Step 4: Follow redirect to mock IdP
	req4, err := http.NewRequestWithContext(t.Context(), http.MethodGet, idpLocation, nil)
	require.NoError(t, err)

	resp4, err := client.Do(req4)
	require.NoError(t, err)
	defer resp4.Body.Close()

	// Mock IdP should return a form that posts back to proxy ACS
	body := new(bytes.Buffer)
	_, err = body.ReadFrom(resp4.Body)
	require.NoError(t, err)

	// Extract form values
	formAction, samlResponse, relayState := extractFormValues(t, body.String())
	require.NotEmpty(t, formAction)
	require.NotEmpty(t, samlResponse)

	// Step 5: Post SAML response back to proxy ACS
	formData := url.Values{}
	formData.Set("SAMLResponse", samlResponse)
	formData.Set("RelayState", relayState)

	req5, err := http.NewRequestWithContext(t.Context(), http.MethodPost, formAction, strings.NewReader(formData.Encode()))
	require.NoError(t, err)
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		req5.AddCookie(cookie)
	}

	resp5, err := client.Do(req5)
	require.NoError(t, err)
	defer resp5.Body.Close()

	// Should redirect to callback
	require.Equal(t, http.StatusFound, resp5.StatusCode)
	callbackLocation := resp5.Header.Get("Location")
	require.Contains(t, callbackLocation, "/callback")

	// Step 6: Follow redirect to callback
	req6, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+callbackLocation, nil)
	require.NoError(t, err)
	for _, cookie := range cookies {
		req6.AddCookie(cookie)
	}
	for _, cookie := range resp5.Cookies() {
		req6.AddCookie(cookie)
	}

	resp6, err := client.Do(req6)
	require.NoError(t, err)
	defer resp6.Body.Close()

	// Should return a form that posts to the original SP
	body6 := new(bytes.Buffer)
	_, err = body6.ReadFrom(resp6.Body)
	require.NoError(t, err)

	// Extract the final SAML response that goes to the SP
	_, finalSAMLResponse, _ := extractFormValues(t, body6.String())
	require.NotEmpty(t, finalSAMLResponse)

	// Step 7: Decode and verify the final SAML response contains our custom attributes
	decodedResponse, err := base64.StdEncoding.DecodeString(finalSAMLResponse)
	require.NoError(t, err)

	var response saml.Response
	err = xml.Unmarshal(decodedResponse, &response)
	require.NoError(t, err)

	// Verify the response contains our custom attributes
	require.NotNil(t, response.Assertion)
	require.NotNil(t, response.Assertion.Subject)
	require.NotNil(t, response.Assertion.Subject.NameID)

	// Check NameID
	assert.Equal(t, customAttrs["nameID"], response.Assertion.Subject.NameID.Value)

	// Check attributes
	require.NotEmpty(t, response.Assertion.AttributeStatements)
	attrs := response.Assertion.AttributeStatements[0].Attributes

	// Create a map for easier assertion
	attrMap := make(map[string]string)
	for _, attr := range attrs {
		if len(attr.Values) > 0 {
			attrMap[attr.Name] = attr.Values[0].Value
		}
	}

	// Verify all custom attributes are present
	assert.Equal(t, customAttrs["email"], attrMap["Email"])
	assert.Equal(t, customAttrs["name"], attrMap["FullName"])
	assert.Equal(t, customAttrs["givenName"], attrMap["GivenName"])
	assert.Equal(t, customAttrs["surname"], attrMap["Surname"])

	// Also verify the UserID is set correctly
	assert.Equal(t, customAttrs["nameID"], attrMap["UserID"])
}

// TestAssertionDataWithDifferentAttributeNames tests attribute mapping with various attribute names.
func TestAssertionDataWithDifferentAttributeNames(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := generateTestCertificate(t)

	// Create mock IdP
	mockIDP := NewMockSAMLProvider(t)
	defer mockIDP.Close()

	// Test different attribute name variations
	testCases := []struct {
		name            string
		idpAttributes   map[string]string
		expectedSPAttrs map[string]string
	}{
		{
			name: "Standard attribute names",
			idpAttributes: map[string]string{
				"nameID":    "user1@example.com",
				"email":     "user1@example.com",
				"name":      "User One",
				"givenName": "User",
				"surname":   "One",
			},
			expectedSPAttrs: map[string]string{
				"UserID":    "user1@example.com",
				"Email":     "user1@example.com",
				"FullName":  "User One",
				"GivenName": "User",
				"Surname":   "One",
			},
		},
		{
			name: "Alternative attribute names",
			idpAttributes: map[string]string{
				"nameID":      "user2@example.com",
				"mail":        "user2@example.com",
				"displayName": "User Two",
				"firstName":   "User",
				"lastName":    "Two",
			},
			expectedSPAttrs: map[string]string{
				"UserID":    "user2@example.com",
				"Email":     "user2@example.com",
				"FullName":  "User Two",
				"GivenName": "User",
				"Surname":   "Two",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Update mock IdP attributes
			mockIDP.SetUserAttributes(tc.idpAttributes)

			// Set up environment
			envVars := map[string]string{
				"PROXY_ENTITY_ID":              "http://localhost:8080",
				"PROXY_ACS_URL":                "http://localhost:8080/saml/acs",
				"PROXY_METADATA_URL":           "http://localhost:8080/metadata",
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

			// Load config and create components
			cfg, err := config.LoadConfig()
			require.NoError(t, err)

			// Create service providers
			providers, err := proxySAML.CreateServiceProviders(t.Context(), cfg)
			require.NoError(t, err)

			// Create proxy IDP
			idp, err := proxySAML.CreateProxyIDP(cfg)
			require.NoError(t, err)

			// Create a test auth request with assertion
			authRequest := &proxySAML.AuthRequest{
				ID:                       "test-auth-request",
				ApplicationID:            "test-app",
				RelayState:               "test-state",
				AccessConsumerServiceURL: "https://sp.example.com/acs",
				BindingType:              "HTTP-POST",
				AuthRequestID:            "test-request-id",
				Issuer:                   "https://sp.example.com",
				UserID:                   tc.idpAttributes["nameID"],
				IsDone:                   true,
				Assertion: &saml.Assertion{
					Subject: &saml.Subject{
						NameID: &saml.NameID{
							Value: tc.idpAttributes["nameID"],
						},
					},
					AttributeStatements: []saml.AttributeStatement{
						{
							Attributes: createAttributesFromMap(tc.idpAttributes),
						},
					},
				},
			}

			// Add auth request to storage
			idp.GetStorage().AddAuthRequestForTesting(authRequest)

			// Test SetUserinfoWithUserID
			userinfo := &mockAttributeSetter{
				attributes: make(map[string]string),
			}

			err = idp.GetStorage().SetUserinfoWithUserID(
				t.Context(),
				authRequest.ID,
				userinfo,
				authRequest.UserID,
				nil,
			)
			require.NoError(t, err)

			// Verify attributes were set correctly
			for key, expectedValue := range tc.expectedSPAttrs {
				assert.Equal(t, expectedValue, userinfo.attributes[key],
					"Attribute %s should be %s", key, expectedValue)
			}

			// Cleanup - just verify we created the handler without errors
			_ = proxy.SetupHTTPHandlers(idp, providers, cfg)
		})
	}
}

// Helper function to create SAML attributes from a map.
func createAttributesFromMap(attrs map[string]string) []saml.Attribute {
	attributes := make([]saml.Attribute, 0, len(attrs))

	// Map our test attributes to various possible SAML attribute names
	attrMapping := map[string][]string{
		"email":     {"email", "mail"},
		"name":      {"name", "displayName"},
		"givenName": {"givenName", "firstName"},
		"surname":   {"surname", "lastName", "sn"},
	}

	for key, value := range attrs {
		if key == "nameID" {
			continue // Skip nameID as it's handled separately
		}

		// Find which attribute name to use
		attrName := key
		for _, variants := range attrMapping {
			for _, variant := range variants {
				if key == variant {
					attrName = variant

					break
				}
			}
		}

		attributes = append(attributes, saml.Attribute{
			Name:       attrName,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []saml.AttributeValue{
				{Value: value},
			},
		})
	}

	return attributes
}

// mockAttributeSetter implements models.AttributeSetter for testing.
type mockAttributeSetter struct {
	attributes map[string]string
}

func (m *mockAttributeSetter) SetUserID(id string) {
	m.attributes["UserID"] = id
}

func (m *mockAttributeSetter) SetUsername(username string) {
	m.attributes["Username"] = username
}

func (m *mockAttributeSetter) SetEmail(email string) {
	m.attributes["Email"] = email
}

func (m *mockAttributeSetter) SetFullName(name string) {
	m.attributes["FullName"] = name
}

func (m *mockAttributeSetter) SetGivenName(name string) {
	m.attributes["GivenName"] = name
}

func (m *mockAttributeSetter) SetSurname(name string) {
	m.attributes["Surname"] = name
}

func (m *mockAttributeSetter) SetNickName(name string) {
	m.attributes["NickName"] = name
}

func (m *mockAttributeSetter) SetDisplayName(name string) {
	m.attributes["DisplayName"] = name
}

func (m *mockAttributeSetter) SetPreferredLanguage(lang string) {
	m.attributes["PreferredLanguage"] = lang
}

func (m *mockAttributeSetter) SetPhone(phone string) {
	m.attributes["Phone"] = phone
}

func (m *mockAttributeSetter) SetPhoneVerified(verified bool) {
	if verified {
		m.attributes["PhoneVerified"] = "true"
	} else {
		m.attributes["PhoneVerified"] = "false"
	}
}

func (m *mockAttributeSetter) SetEmailVerified(verified bool) {
	if verified {
		m.attributes["EmailVerified"] = "true"
	} else {
		m.attributes["EmailVerified"] = "false"
	}
}

func (m *mockAttributeSetter) SetPreferredUsername(username string) {
	m.attributes["PreferredUsername"] = username
}

func (m *mockAttributeSetter) SetAvatarURL(url string) {
	m.attributes["AvatarURL"] = url
}

func (m *mockAttributeSetter) SetLocale(locale string) {
	m.attributes["Locale"] = locale
}

func (m *mockAttributeSetter) SetCustomAttribute(name, _, _ string, attributeValue []string) {
	if len(attributeValue) > 0 {
		m.attributes[name] = attributeValue[0]
	}
}

func (m *mockAttributeSetter) GetCustomAttribute(key string) string {
	return m.attributes[key]
}

func (m *mockAttributeSetter) GetCustomAttributeKeys() []string {
	keys := make([]string, 0, len(m.attributes))
	for k := range m.attributes {
		keys = append(keys, k)
	}

	return keys
}
