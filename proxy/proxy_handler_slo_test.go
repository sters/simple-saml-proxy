package proxy

import (
	"compress/flate"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleSLO(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	// Create test configuration
	cfg := config.Config{
		IDP: []config.IDPConfig{
			{
				ID:              "test_idp",
				EntityID:        "https://idp.example.com",
				CertificatePath: certPath,
			},
		},
	}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.PrivateKeyPath = keyPath
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{
			EntityID: "https://sp.example.com",
		},
	}

	// Create service providers
	ctx := t.Context()
	sps, err := saml.CreateServiceProviders(ctx, cfg)
	require.NoError(t, err)

	// Create test IDP
	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	// Create handler
	handler := handleSLO(idp, sps)

	tests := []struct {
		name           string
		method         string
		samlRequest    string
		relayState     string
		expectedStatus int
		expectedBody   string
		checkCookie    bool
	}{
		{
			name:           "Missing SAMLRequest parameter",
			method:         http.MethodGet,
			samlRequest:    "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing SAMLRequest parameter",
		},
		{
			name:           "Invalid base64 SAMLRequest",
			method:         http.MethodGet,
			samlRequest:    "invalid-base64!@#",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid logout request",
		},
		{
			name:           "Invalid XML SAMLRequest",
			method:         http.MethodGet,
			samlRequest:    base64.StdEncoding.EncodeToString([]byte("<invalid>xml</invalid>")),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid logout request",
		},
		{
			name:           "Missing issuer in logout request",
			method:         http.MethodGet,
			samlRequest:    createTestLogoutRequest("", "user123", "session456"),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid logout request",
		},
		{
			name:           "Unauthorized SP issuer",
			method:         http.MethodGet,
			samlRequest:    createTestLogoutRequest("https://unauthorized.example.com", "user123", "session456"),
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Unauthorized service provider",
		},
		{
			name:           "Future issue instant",
			method:         http.MethodGet,
			samlRequest:    createTestLogoutRequestWithTime("https://sp.example.com", "user123", "session456", time.Now().Add(10*time.Minute)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid logout request",
		},
		{
			name:           "Too old issue instant",
			method:         http.MethodGet,
			samlRequest:    createTestLogoutRequestWithTime("https://sp.example.com", "user123", "session456", time.Now().Add(-10*time.Minute)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid logout request",
		},
		{
			name:           "Valid logout request",
			method:         http.MethodGet,
			samlRequest:    createTestLogoutRequest("https://sp.example.com", "user123", "session456"),
			relayState:     "test-relay-state",
			expectedStatus: http.StatusFound,
			expectedBody:   "",
			checkCookie:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request URL
			u := &url.URL{
				Path: "/saml/slo",
			}
			q := u.Query()
			if tt.samlRequest != "" {
				q.Set("SAMLRequest", tt.samlRequest)
			}
			if tt.relayState != "" {
				q.Set("RelayState", tt.relayState)
			}
			u.RawQuery = q.Encode()

			req := httptest.NewRequest(tt.method, u.String(), nil)
			w := httptest.NewRecorder()

			handler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}

			if tt.checkCookie {
				cookies := w.Result().Cookies()
				var logoutCookie *http.Cookie
				for _, cookie := range cookies {
					if cookie.Name == "logout_context_id" {
						logoutCookie = cookie

						break
					}
				}
				assert.NotNil(t, logoutCookie, "Should set logout_context_id cookie")
				assert.NotEmpty(t, logoutCookie.Value)
				assert.Equal(t, "/", logoutCookie.Path)
				assert.True(t, logoutCookie.HttpOnly)
				assert.Equal(t, 300, logoutCookie.MaxAge)

				// Check redirect location
				location := w.Header().Get("Location")
				assert.Equal(t, "/logout_idp_select", location)
			}
		})
	}
}

func TestParseLogoutRequest(t *testing.T) {
	tests := []struct {
		name           string
		samlRequest    string
		expectedError  string
		expectedIssuer string
	}{
		{
			name:          "Invalid base64",
			samlRequest:   "invalid-base64!@#",
			expectedError: "failed to base64 decode logout request",
		},
		{
			name:          "Invalid XML",
			samlRequest:   base64.StdEncoding.EncodeToString([]byte("<invalid>xml</invalid>")),
			expectedError: "failed to unmarshal logout request",
		},
		{
			name:          "Missing issuer",
			samlRequest:   createTestLogoutRequest("", "user123", "session456"),
			expectedError: "logout request missing issuer",
		},
		{
			name:           "Valid logout request",
			samlRequest:    createTestLogoutRequest("https://sp.example.com", "user123", "session456"),
			expectedIssuer: "https://sp.example.com",
		},
		{
			name:           "Valid logout request with compressed data",
			samlRequest:    createCompressedLogoutRequest("https://sp.example.com", "user123", "session456"),
			expectedIssuer: "https://sp.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logoutRequest, err := parseLogoutRequest(tt.samlRequest)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, logoutRequest)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, logoutRequest)
				assert.Equal(t, tt.expectedIssuer, logoutRequest.Issuer.Value)
			}
		})
	}
}

func TestDecodeDeflatedRequest(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedError bool
	}{
		{
			name:          "Valid compressed data",
			input:         compressData([]byte("<test>data</test>")),
			expectedError: false,
		},
		{
			name:          "Invalid compressed data",
			input:         []byte("invalid compressed data"),
			expectedError: true,
		},
		{
			name:          "Empty data",
			input:         []byte{},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeDeflatedRequest(tt.input)

			if tt.expectedError {
				require.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestGetNameIDValue(t *testing.T) {
	tests := []struct {
		name     string
		request  *crewjamsaml.LogoutRequest
		expected string
	}{
		{
			name: "With NameID",
			request: &crewjamsaml.LogoutRequest{
				NameID: &crewjamsaml.NameID{
					Value: "user123",
				},
			},
			expected: "user123",
		},
		{
			name:     "Without NameID",
			request:  &crewjamsaml.LogoutRequest{},
			expected: "",
		},
		{
			name: "Empty NameID value",
			request: &crewjamsaml.LogoutRequest{
				NameID: &crewjamsaml.NameID{
					Value: "",
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getNameIDValue(tt.request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSessionIndex(t *testing.T) {
	tests := []struct {
		name     string
		request  *crewjamsaml.LogoutRequest
		expected string
	}{
		{
			name: "With SessionIndex",
			request: &crewjamsaml.LogoutRequest{
				SessionIndex: &crewjamsaml.SessionIndex{
					Value: "session123",
				},
			},
			expected: "session123",
		},
		{
			name:     "Without SessionIndex",
			request:  &crewjamsaml.LogoutRequest{},
			expected: "",
		},
		{
			name: "Empty SessionIndex value",
			request: &crewjamsaml.LogoutRequest{
				SessionIndex: &crewjamsaml.SessionIndex{
					Value: "",
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getSessionIndex(tt.request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateIssueInstant(t *testing.T) {
	tests := []struct {
		name          string
		issueInstant  time.Time
		expectedError string
	}{
		{
			name:         "Valid recent time",
			issueInstant: time.Now().Add(-1 * time.Minute),
		},
		{
			name:          "Future time",
			issueInstant:  time.Now().Add(1 * time.Minute),
			expectedError: "logout request issue instant is in the future",
		},
		{
			name:          "Too old time",
			issueInstant:  time.Now().Add(-10 * time.Minute),
			expectedError: "logout request is too old",
		},
		{
			name:         "Edge case - exactly 5 minutes old",
			issueInstant: time.Now().Add(-5*time.Minute + time.Second),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIssueInstant(tt.issueInstant)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper functions for creating test data

func createTestLogoutRequest(issuer, nameID, sessionIndex string) string {
	return createTestLogoutRequestWithTime(issuer, nameID, sessionIndex, time.Now())
}

func createTestLogoutRequestWithTime(issuer, nameID, sessionIndex string, issueInstant time.Time) string {
	var issuerXML string
	if issuer != "" {
		issuerXML = fmt.Sprintf(`<saml:Issuer>%s</saml:Issuer>`, issuer)
	}

	var nameIDXML string
	if nameID != "" {
		nameIDXML = fmt.Sprintf(`<saml:NameID>%s</saml:NameID>`, nameID)
	}

	var sessionIndexXML string
	if sessionIndex != "" {
		sessionIndexXML = fmt.Sprintf(`<samlp:SessionIndex>%s</samlp:SessionIndex>`, sessionIndex)
	}

	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="test_logout_request_123"
                     Version="2.0"
                     IssueInstant="%s"
                     Destination="https://proxy.example.com/saml/slo">
    %s
    %s
    %s
</samlp:LogoutRequest>`, issueInstant.Format(time.RFC3339), issuerXML, nameIDXML, sessionIndexXML)

	return base64.StdEncoding.EncodeToString([]byte(xml))
}

func createCompressedLogoutRequest(issuer, nameID, sessionIndex string) string {
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="test_logout_request_compressed"
                     Version="2.0"
                     IssueInstant="%s"
                     Destination="https://proxy.example.com/saml/slo">
    <saml:Issuer>%s</saml:Issuer>
    <saml:NameID>%s</saml:NameID>
    <samlp:SessionIndex>%s</samlp:SessionIndex>
</samlp:LogoutRequest>`, time.Now().Format(time.RFC3339), issuer, nameID, sessionIndex)

	compressed := compressData([]byte(xml))

	return base64.StdEncoding.EncodeToString(compressed)
}

func compressData(data []byte) []byte {
	var buf strings.Builder
	writer, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = writer.Write(data)
	_ = writer.Close()

	return []byte(buf.String())
}
