package proxy

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLogoutResponse(t *testing.T) {
	// Create a valid logout response
	validResponse := &crewjamsaml.LogoutResponse{
		XMLName: xml.Name{
			Space: "urn:oasis:names:tc:SAML:2.0:protocol",
			Local: "LogoutResponse",
		},
		ID:           "_test-logout-response",
		Version:      "2.0",
		IssueInstant: time.Now(),
		Issuer: &crewjamsaml.Issuer{
			Value: "https://sp.example.com",
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}

	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errMsg    string
		checkResp func(t *testing.T, resp *crewjamsaml.LogoutResponse)
	}{
		{
			name: "Valid compressed logout response",
			input: func() string {
				xmlBytes, _ := xml.Marshal(validResponse)
				compressed, _ := deflateCompress(xmlBytes)

				return base64.StdEncoding.EncodeToString(compressed)
			}(),
			wantErr: false,
			checkResp: func(t *testing.T, resp *crewjamsaml.LogoutResponse) {
				t.Helper()
				assert.Equal(t, "_test-logout-response", resp.ID)
				assert.Equal(t, "https://sp.example.com", resp.Issuer.Value)
				assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Success", resp.Status.StatusCode.Value)
			},
		},
		{
			name: "Valid uncompressed logout response",
			input: func() string {
				xmlBytes, _ := xml.Marshal(validResponse)

				return base64.StdEncoding.EncodeToString(xmlBytes)
			}(),
			wantErr: false,
			checkResp: func(t *testing.T, resp *crewjamsaml.LogoutResponse) {
				t.Helper()
				assert.Equal(t, "_test-logout-response", resp.ID)
			},
		},
		{
			name:    "Invalid base64",
			input:   "!!!invalid-base64!!!",
			wantErr: true,
			errMsg:  "failed to base64 decode",
		},
		{
			name:    "Invalid XML",
			input:   base64.StdEncoding.EncodeToString([]byte("<invalid>not a logout response</invalid>")),
			wantErr: true,
			errMsg:  "failed to unmarshal logout response",
		},
		{
			name:    "Corrupted compressed data",
			input:   base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF, 0xFF}),
			wantErr: true,
			errMsg:  "failed to unmarshal logout response",
		},
		{
			name:    "Empty input",
			input:   "",
			wantErr: true,
			errMsg:  "failed to unmarshal logout response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := parseLogoutResponse(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resp)
				if tt.checkResp != nil {
					tt.checkResp(t, resp)
				}
			}
		})
	}
}

func TestValidateResponseIssueInstant(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		issueInstant time.Time
		wantErr      bool
		errType      error
	}{
		{
			name:         "Valid - just issued",
			issueInstant: now,
			wantErr:      false,
		},
		{
			name:         "Valid - 1 minute ago",
			issueInstant: now.Add(-1 * time.Minute),
			wantErr:      false,
		},
		{
			name:         "Valid - 4 minutes ago",
			issueInstant: now.Add(-4 * time.Minute),
			wantErr:      false,
		},
		{
			name:         "Invalid - too old (6 minutes)",
			issueInstant: now.Add(-6 * time.Minute),
			wantErr:      true,
			errType:      errResponseTooOld,
		},
		{
			name:         "Invalid - too old (1 hour)",
			issueInstant: now.Add(-1 * time.Hour),
			wantErr:      true,
			errType:      errResponseTooOld,
		},
		{
			name:         "Invalid - future time (1 minute)",
			issueInstant: now.Add(1 * time.Minute),
			wantErr:      true,
			errType:      errResponseIssueInstantInFuture,
		},
		{
			name:         "Invalid - future time (1 hour)",
			issueInstant: now.Add(1 * time.Hour),
			wantErr:      true,
			errType:      errResponseIssueInstantInFuture,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResponseIssueInstant(tt.issueInstant)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetLogoutResponseStatus(t *testing.T) {
	tests := []struct {
		name     string
		response *crewjamsaml.LogoutResponse
		want     string
	}{
		{
			name: "Success status",
			response: &crewjamsaml.LogoutResponse{
				Status: crewjamsaml.Status{
					StatusCode: crewjamsaml.StatusCode{
						Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
					},
				},
			},
			want: "urn:oasis:names:tc:SAML:2.0:status:Success",
		},
		{
			name: "Error status",
			response: &crewjamsaml.LogoutResponse{
				Status: crewjamsaml.Status{
					StatusCode: crewjamsaml.StatusCode{
						Value: "urn:oasis:names:tc:SAML:2.0:status:Responder",
					},
				},
			},
			want: "urn:oasis:names:tc:SAML:2.0:status:Responder",
		},
		{
			name: "Empty status",
			response: &crewjamsaml.LogoutResponse{
				Status: crewjamsaml.Status{
					StatusCode: crewjamsaml.StatusCode{
						Value: "",
					},
				},
			},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getLogoutResponseStatus(tt.response)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildLogoutResponseURL(t *testing.T) {
	response := &crewjamsaml.LogoutResponse{
		XMLName: xml.Name{
			Space: "urn:oasis:names:tc:SAML:2.0:protocol",
			Local: "LogoutResponse",
		},
		ID:           "_test-response",
		Version:      "2.0",
		IssueInstant: time.Now(),
		Issuer: &crewjamsaml.Issuer{
			Value: "https://proxy.example.com",
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}

	tests := []struct {
		name        string
		destination string
		relayState  string
		wantErr     bool
		checkURL    func(t *testing.T, urlStr string)
	}{
		{
			name:        "Basic URL without relay state",
			destination: "https://idp.example.com/slo/response",
			relayState:  "",
			wantErr:     false,
			checkURL: func(t *testing.T, urlStr string) {
				t.Helper()
				u, err := url.Parse(urlStr)
				require.NoError(t, err)
				assert.Equal(t, "https", u.Scheme)
				assert.Equal(t, "idp.example.com", u.Host)
				assert.Equal(t, "/slo/response", u.Path)
				assert.NotEmpty(t, u.Query().Get("SAMLResponse"))
				assert.Empty(t, u.Query().Get("RelayState"))
			},
		},
		{
			name:        "URL with relay state",
			destination: "https://idp.example.com/slo/response",
			relayState:  "some-relay-state-value",
			wantErr:     false,
			checkURL: func(t *testing.T, urlStr string) {
				t.Helper()
				u, err := url.Parse(urlStr)
				require.NoError(t, err)
				assert.Equal(t, "some-relay-state-value", u.Query().Get("RelayState"))
			},
		},
		{
			name:        "URL with existing query parameters",
			destination: "https://idp.example.com/slo/response?existing=param",
			relayState:  "",
			wantErr:     false,
			checkURL: func(t *testing.T, urlStr string) {
				t.Helper()
				u, err := url.Parse(urlStr)
				require.NoError(t, err)
				assert.Equal(t, "param", u.Query().Get("existing"))
				assert.NotEmpty(t, u.Query().Get("SAMLResponse"))
			},
		},
		{
			name:        "Invalid destination URL",
			destination: "://invalid-url",
			relayState:  "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlStr, err := buildLogoutResponseURL(response, tt.destination, tt.relayState)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, urlStr)
				if tt.checkURL != nil {
					tt.checkURL(t, urlStr)
				}

				// Verify the SAML response is properly encoded
				u, _ := url.Parse(urlStr)
				samlResponse := u.Query().Get("SAMLResponse")
				assert.NotEmpty(t, samlResponse)

				// Decode and verify
				decoded, err := base64.StdEncoding.DecodeString(samlResponse)
				require.NoError(t, err)
				assert.NotEmpty(t, decoded)
			}
		})
	}
}

func TestHandleSLOResponse(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	// Create test logout context
	storage := idp.GetStorage()
	logoutCtx := storage.CreateLogoutContext("idp", "https://idp.example.com", "https://sp.example.com", "test-relay-state")

	// Create handler
	handler := handleSLOResponse(idp, nil)

	// Create a valid logout response
	logoutResponse := &crewjamsaml.LogoutResponse{
		XMLName: xml.Name{
			Space: "urn:oasis:names:tc:SAML:2.0:protocol",
			Local: "LogoutResponse",
		},
		ID:           "_test-response",
		Version:      "2.0",
		IssueInstant: time.Now(),
		Issuer: &crewjamsaml.Issuer{
			Value: "https://sp.example.com",
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "Valid logout response",
			setupRequest: func() *http.Request {
				xmlBytes, _ := xml.Marshal(logoutResponse)
				compressed, _ := deflateCompress(xmlBytes)
				encoded := base64.StdEncoding.EncodeToString(compressed)

				req := httptest.NewRequest(http.MethodGet, "/slo/response?SAMLResponse="+url.QueryEscape(encoded), nil)
				req.AddCookie(&http.Cookie{
					Name:  "logout_context_id",
					Value: logoutCtx.ID,
				})

				return req
			},
			expectedStatus: http.StatusFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				// Check redirect
				location := w.Header().Get("Location")
				assert.NotEmpty(t, location)
				assert.Contains(t, location, "https://idp.example.com/slo/response")
				assert.Contains(t, location, "SAMLResponse=")
				assert.Contains(t, location, "RelayState=test-relay-state")

				// Check cookies are cleared
				cookies := w.Result().Cookies()
				for _, cookie := range cookies {
					if cookie.Name == "logout_context_id" || cookie.Name == "logout_sp_id" || cookie.Name == "logout_name_id" {
						assert.Equal(t, -1, cookie.MaxAge)
					}
				}
			},
		},
		{
			name: "Missing SAMLResponse parameter",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/slo/response", nil)
				req.AddCookie(&http.Cookie{
					Name:  "logout_context_id",
					Value: logoutCtx.ID,
				})

				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Missing SAMLResponse parameter")
			},
		},
		{
			name: "Invalid SAMLResponse",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/slo/response?SAMLResponse=invalid-base64", nil)
				req.AddCookie(&http.Cookie{
					Name:  "logout_context_id",
					Value: logoutCtx.ID,
				})

				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Invalid logout response")
			},
		},
		{
			name: "Response too old",
			setupRequest: func() *http.Request {
				oldResponse := *logoutResponse
				oldResponse.IssueInstant = time.Now().Add(-10 * time.Minute)

				xmlBytes, _ := xml.Marshal(&oldResponse)
				compressed, _ := deflateCompress(xmlBytes)
				encoded := base64.StdEncoding.EncodeToString(compressed)

				req := httptest.NewRequest(http.MethodGet, "/slo/response?SAMLResponse="+url.QueryEscape(encoded), nil)
				req.AddCookie(&http.Cookie{
					Name:  "logout_context_id",
					Value: logoutCtx.ID,
				})

				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Invalid logout response")
			},
		},
		{
			name: "Missing logout context cookie",
			setupRequest: func() *http.Request {
				xmlBytes, _ := xml.Marshal(logoutResponse)
				compressed, _ := deflateCompress(xmlBytes)
				encoded := base64.StdEncoding.EncodeToString(compressed)

				req := httptest.NewRequest(http.MethodGet, "/slo/response?SAMLResponse="+url.QueryEscape(encoded), nil)
				// No cookie added
				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Invalid logout response")
			},
		},
		{
			name: "Invalid logout context ID",
			setupRequest: func() *http.Request {
				xmlBytes, _ := xml.Marshal(logoutResponse)
				compressed, _ := deflateCompress(xmlBytes)
				encoded := base64.StdEncoding.EncodeToString(compressed)

				req := httptest.NewRequest(http.MethodGet, "/slo/response?SAMLResponse="+url.QueryEscape(encoded), nil)
				req.AddCookie(&http.Cookie{
					Name:  "logout_context_id",
					Value: "non-existent-context",
				})

				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Invalid logout response")
			},
		},
		{
			name: "Response with error status",
			setupRequest: func() *http.Request {
				// Create a new context for this test
				storage := idp.GetStorage()
				testCtx := storage.CreateLogoutContext("idp", "https://idp.example.com", "https://sp.example.com", "test-relay-state")

				errorResponse := *logoutResponse
				errorResponse.Status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Responder"

				xmlBytes, _ := xml.Marshal(&errorResponse)
				compressed, _ := deflateCompress(xmlBytes)
				encoded := base64.StdEncoding.EncodeToString(compressed)

				req := httptest.NewRequest(http.MethodGet, "/slo/response?SAMLResponse="+url.QueryEscape(encoded), nil)
				req.AddCookie(&http.Cookie{
					Name:  "logout_context_id",
					Value: testCtx.ID,
				})

				return req
			},
			expectedStatus: http.StatusFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				// Should still redirect but with error status
				location := w.Header().Get("Location")
				assert.NotEmpty(t, location)

				// Decode the response to check status
				u, _ := url.Parse(location)
				samlResp := u.Query().Get("SAMLResponse")
				decoded, _ := base64.StdEncoding.DecodeString(samlResp)
				decompressed, _ := decodeDeflatedData(decoded)

				assert.Contains(t, string(decompressed), "urn:oasis:names:tc:SAML:2.0:status:Responder")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			w := httptest.NewRecorder()

			handler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestDecodeDeflatedData(t *testing.T) {
	originalData := []byte("This is test data for compression testing with some repetition ")

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name: "Valid compressed data",
			input: func() []byte {
				compressed, _ := deflateCompress(originalData)

				return compressed
			}(),
			wantErr: false,
		},
		{
			name:    "Invalid compressed data",
			input:   []byte{0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: true,
		},
		{
			name:    "Empty data",
			input:   []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeDeflatedData(tt.input)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, originalData, result)
			}
		})
	}
}

func TestDecodeDeflatedData_LargeData(t *testing.T) {
	// Create data larger than 10MB
	largeData := make([]byte, 11*1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	compressed, err := deflateCompress(largeData)
	require.NoError(t, err)

	// Should read up to the limit
	result, err := decodeDeflatedData(compressed)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(result), 10*1024*1024)
}

func TestHandleSLOResponse_Integration(t *testing.T) {
	// This test verifies the full flow including the final redirect URL parsing
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	// Create logout context with special characters in RelayState
	storage := idp.GetStorage()
	logoutCtx := storage.CreateLogoutContext("idp", "https://idp.example.com", "https://sp.example.com", "relay=state&with=special%20chars")

	handler := handleSLOResponse(idp, nil)

	// Create response
	logoutResponse := &crewjamsaml.LogoutResponse{
		XMLName: xml.Name{
			Space: "urn:oasis:names:tc:SAML:2.0:protocol",
			Local: "LogoutResponse",
		},
		ID:           "_response",
		Version:      "2.0",
		IssueInstant: time.Now(),
		Issuer: &crewjamsaml.Issuer{
			Value: "https://sp.example.com",
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}

	xmlBytes, _ := xml.Marshal(logoutResponse)
	compressed, _ := deflateCompress(xmlBytes)
	encoded := base64.StdEncoding.EncodeToString(compressed)

	req := httptest.NewRequest(http.MethodGet, "/slo/response?SAMLResponse="+url.QueryEscape(encoded), nil)
	req.AddCookie(&http.Cookie{
		Name:  "logout_context_id",
		Value: logoutCtx.ID,
	})
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")

	// Parse the redirect URL
	u, err := url.Parse(location)
	require.NoError(t, err)

	// Verify RelayState is properly encoded
	assert.Equal(t, "relay=state&with=special%20chars", u.Query().Get("RelayState"))

	// Verify the logout context was deleted
	_, err = storage.GetLogoutContext(logoutCtx.ID)
	assert.Error(t, err)
}
