package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleLogoutIDPSelected(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	// Create test configuration
	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Create IDP
	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	// Create service providers with metadata
	providers := &saml.ServiceProviders{
		Providers: map[string]*saml.ServiceProvider{
			"idp1": {
				ID: "idp1",
				Middleware: &samlsp.Middleware{
					ServiceProvider: crewjamsaml.ServiceProvider{
						IDPMetadata: &crewjamsaml.EntityDescriptor{
							IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{
								{
									SSODescriptor: crewjamsaml.SSODescriptor{
										RoleDescriptor: crewjamsaml.RoleDescriptor{},
										SingleLogoutServices: []crewjamsaml.Endpoint{
											{
												Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
												Location: "https://idp1.example.com/slo",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"idp2": {
				ID: "idp2",
				Middleware: &samlsp.Middleware{
					ServiceProvider: crewjamsaml.ServiceProvider{
						// No metadata - to test error case
					},
				},
			},
			"idp3": {
				ID: "idp3",
				Middleware: &samlsp.Middleware{
					ServiceProvider: crewjamsaml.ServiceProvider{
						IDPMetadata: &crewjamsaml.EntityDescriptor{
							IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{
								{
									SSODescriptor: crewjamsaml.SSODescriptor{
										// No SingleLogoutServices
									},
								},
							},
						},
					},
				},
			},
		},
	}

	handler := handleLogoutIDPSelected(idp, providers)

	tests := []struct {
		name            string
		setupContext    func() string
		idpID           string
		cookie          *http.Cookie
		wantStatus      int
		wantRedirect    bool
		checkRedirectFn func(t *testing.T, location string)
	}{
		{
			name: "Valid IdP selection",
			setupContext: func() string {
				storage := idp.GetStorage()
				ctx := storage.CreateLogoutContext("sp", "sp1", "", "")

				return ctx.ID
			},
			idpID:        "idp1",
			wantStatus:   http.StatusFound,
			wantRedirect: true,
			checkRedirectFn: func(t *testing.T, location string) {
				t.Helper()
				assert.Contains(t, location, "https://idp1.example.com/slo")
				assert.Contains(t, location, "SAMLRequest=")

				// Parse and validate the logout request
				u, err := url.Parse(location)
				require.NoError(t, err)

				samlRequest := u.Query().Get("SAMLRequest")
				assert.NotEmpty(t, samlRequest)

				// Decode and decompress the request
				compressed, err := base64.StdEncoding.DecodeString(samlRequest)
				require.NoError(t, err)

				xmlData, err := decodeDeflatedRequest(compressed)
				require.NoError(t, err)

				var logoutReq crewjamsaml.LogoutRequest
				err = xml.Unmarshal(xmlData, &logoutReq)
				require.NoError(t, err)

				assert.Equal(t, "https://proxy.example.com", logoutReq.Issuer.Value)
				assert.Equal(t, "https://idp1.example.com/slo", logoutReq.Destination)
			},
		},
		{
			name: "Missing logout context cookie",
			setupContext: func() string {
				return ""
			},
			idpID:      "idp1",
			cookie:     nil,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid logout context ID",
			setupContext: func() string {
				return "invalid-id"
			},
			idpID:      "idp1",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Missing IdP ID",
			setupContext: func() string {
				storage := idp.GetStorage()
				ctx := storage.CreateLogoutContext("sp", "sp1", "", "")

				return ctx.ID
			},
			idpID:      "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid IdP ID",
			setupContext: func() string {
				storage := idp.GetStorage()
				ctx := storage.CreateLogoutContext("sp", "sp1", "", "")

				return ctx.ID
			},
			idpID:      "invalid-idp",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "IdP without metadata",
			setupContext: func() string {
				storage := idp.GetStorage()
				ctx := storage.CreateLogoutContext("sp", "sp1", "", "")

				return ctx.ID
			},
			idpID:      "idp2",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "IdP without SLO service",
			setupContext: func() string {
				storage := idp.GetStorage()
				ctx := storage.CreateLogoutContext("sp", "sp1", "", "")

				return ctx.ID
			},
			idpID:      "idp3",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			contextID := tt.setupContext()

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/logout/idp", strings.NewReader("idpID="+tt.idpID))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			// Add cookie if context ID is set
			if contextID != "" {
				if tt.cookie != nil {
					req.AddCookie(tt.cookie)
				} else {
					req.AddCookie(&http.Cookie{
						Name:  "logout_context_id",
						Value: contextID,
					})
				}
			}

			// Execute
			w := httptest.NewRecorder()
			handler(w, req)

			// Assert
			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantRedirect {
				location := w.Header().Get("Location")
				assert.NotEmpty(t, location)
				if tt.checkRedirectFn != nil {
					tt.checkRedirectFn(t, location)
				}

				// Check for IdP cookie
				cookies := w.Result().Cookies()
				var foundIDPCookie bool
				for _, cookie := range cookies {
					if cookie.Name == "logout_idp_id" && cookie.Value == tt.idpID {
						foundIDPCookie = true

						break
					}
				}
				assert.True(t, foundIDPCookie, "Should set logout_idp_id cookie")
			}
		})
	}
}

func TestBuildLogoutURL(t *testing.T) {
	logoutRequest := &crewjamsaml.LogoutRequest{
		ID:           "test123",
		IssueInstant: time.Now(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: "https://proxy.example.com",
		},
		NameID: &crewjamsaml.NameID{
			Value:  "user@example.com",
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
		},
		Destination: "https://idp.example.com/slo",
	}

	tests := []struct {
		name        string
		destination string
		relayState  string
		wantErr     bool
		checkFn     func(t *testing.T, urlStr string)
	}{
		{
			name:        "Without RelayState",
			destination: "https://idp.example.com/slo",
			relayState:  "",
			wantErr:     false,
			checkFn: func(t *testing.T, urlStr string) {
				t.Helper()
				u, err := url.Parse(urlStr)
				require.NoError(t, err)
				assert.Equal(t, "https://idp.example.com/slo", u.Scheme+"://"+u.Host+u.Path)
				assert.NotEmpty(t, u.Query().Get("SAMLRequest"))
				assert.Empty(t, u.Query().Get("RelayState"))
			},
		},
		{
			name:        "With RelayState",
			destination: "https://idp.example.com/slo",
			relayState:  "test-relay-state",
			wantErr:     false,
			checkFn: func(t *testing.T, urlStr string) {
				t.Helper()
				u, err := url.Parse(urlStr)
				require.NoError(t, err)
				assert.Equal(t, "https://idp.example.com/slo", u.Scheme+"://"+u.Host+u.Path)
				assert.NotEmpty(t, u.Query().Get("SAMLRequest"))
				assert.Equal(t, "test-relay-state", u.Query().Get("RelayState"))
			},
		},
		{
			name:        "Invalid destination URL",
			destination: ":",
			relayState:  "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlStr, err := buildLogoutURL(logoutRequest, tt.destination, tt.relayState)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, urlStr)
				if tt.checkFn != nil {
					tt.checkFn(t, urlStr)
				}
			}
		})
	}
}

func TestBuildSignedLogoutURLWithCertificate(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	// Load the certificate to get the private key
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	logoutRequest := &crewjamsaml.LogoutRequest{
		ID:           "test456",
		IssueInstant: time.Now(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: "https://proxy.example.com",
		},
		NameID: &crewjamsaml.NameID{
			Value:  "user@example.com",
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
		},
		Destination: "https://idp.example.com/slo",
	}

	tests := []struct {
		name       string
		relayState string
		sigAlg     string
		checkFn    func(t *testing.T, urlStr string)
	}{
		{
			name:       "With default signature algorithm",
			relayState: "test-relay",
			sigAlg:     "",
			checkFn: func(t *testing.T, urlStr string) {
				t.Helper()
				u, err := url.Parse(urlStr)
				require.NoError(t, err)
				assert.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", u.Query().Get("SigAlg"))
				assert.NotEmpty(t, u.Query().Get("Signature"))
			},
		},
		{
			name:       "With SHA1 signature algorithm",
			relayState: "",
			sigAlg:     sigAlgSHA1,
			checkFn: func(t *testing.T, urlStr string) {
				t.Helper()
				u, err := url.Parse(urlStr)
				require.NoError(t, err)
				assert.Equal(t, sigAlgSHA1, u.Query().Get("SigAlg"))
				assert.NotEmpty(t, u.Query().Get("Signature"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlStr, err := buildSignedLogoutURL(
				logoutRequest,
				"https://idp.example.com/slo",
				tt.relayState,
				cert.PrivateKey,
				tt.sigAlg,
			)

			require.NoError(t, err)
			assert.NotEmpty(t, urlStr)
			if tt.checkFn != nil {
				tt.checkFn(t, urlStr)
			}
		})
	}
}

func TestHandleLogoutIDPSelectedConcurrency(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	// Create test configuration
	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Create IDP
	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	// Create service providers with metadata
	providers := &saml.ServiceProviders{
		Providers: map[string]*saml.ServiceProvider{
			"idp1": {
				ID: "idp1",
				Middleware: &samlsp.Middleware{
					ServiceProvider: crewjamsaml.ServiceProvider{
						IDPMetadata: &crewjamsaml.EntityDescriptor{
							IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{
								{
									SSODescriptor: crewjamsaml.SSODescriptor{
										SingleLogoutServices: []crewjamsaml.Endpoint{
											{
												Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
												Location: "https://idp1.example.com/slo",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	handler := handleLogoutIDPSelected(idp, providers)

	// Setup logout context
	storage := idp.GetStorage()

	// Run concurrent requests
	const numRequests = 10
	done := make(chan bool, numRequests)

	for range numRequests {
		go func() {
			// Create a unique logout context for each request to avoid race conditions
			ctx := storage.CreateLogoutContext("sp", "sp1", "", "")
			contextID := ctx.ID

			req := httptest.NewRequest(http.MethodPost, "/logout/idp", strings.NewReader("idpID=idp1"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{
				Name:  "logout_context_id",
				Value: contextID,
			})

			w := httptest.NewRecorder()
			handler(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for range numRequests {
		<-done
	}
}
