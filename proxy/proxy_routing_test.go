package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyRouting(t *testing.T) {
	// Generate test certificates
	certPath, keyPath := saml.GenerateTestCertificate(t)

	// Test different path configurations
	tests := []struct {
		name     string
		config   config.Config
		requests []struct {
			path           string
			expectedStatus int
			description    string
		}
	}{
		{
			name: "New default paths with /idp and /sp",
			config: config.Config{
				Proxy: struct {
					EntityID                    string            `env:"ENTITY_ID"                      envDefault:"http://localhost:8080"`
					PrivateKeyPath              string            `env:"PRIVATE_KEY_PATH,required"`
					CertificatePath             string            `env:"CERTIFICATE_PATH,required"`
					RequireSignedLogoutRequests bool              `env:"REQUIRE_SIGNED_LOGOUT_REQUESTS" envDefault:"false"`
					AllowedSP                   []config.SPConfig `envPrefix:"ALLOWED_SP_"`
				}{
					EntityID:        "http://localhost:8080",
					PrivateKeyPath:  keyPath,
					CertificatePath: certPath,
				},
			},
			requests: []struct {
				path           string
				expectedStatus int
				description    string
			}{
				{"/ping", http.StatusOK, "Health check endpoint"},
				// IdP endpoints
				{"/idp/metadata", http.StatusOK, "IdP metadata endpoint"},
				{"/idp/slo", http.StatusBadRequest, "IdP SLO endpoint"},
				{"/idp/slo/response", http.StatusBadRequest, "IdP SLO response endpoint"},
				// SP endpoints
				{"/sp/acs", http.StatusBadRequest, "SP ACS endpoint"},
				{"/sp/sls", http.StatusBadRequest, "SP SLS endpoint"},
				{"/sp/idp_select", http.StatusBadRequest, "SP IdP selection page without parameters"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create IDP with test config
			idp, err := saml.CreateProxyIDP(tt.config)
			require.NoError(t, err)

			// Create providers
			providers := &saml.ServiceProviders{
				Providers: make(map[string]*saml.ServiceProvider),
			}

			// Setup HTTP handlers
			handler := SetupHTTPHandlers(idp, providers, tt.config)

			// Test each request
			for _, req := range tt.requests {
				t.Run(req.description, func(t *testing.T) {
					request := httptest.NewRequest(http.MethodGet, req.path, nil)
					recorder := httptest.NewRecorder()

					handler.ServeHTTP(recorder, request)

					assert.Equal(t, req.expectedStatus, recorder.Code,
						"Path %s: expected status %d, got %d",
						req.path, req.expectedStatus, recorder.Code)
				})
			}
		})
	}
}
