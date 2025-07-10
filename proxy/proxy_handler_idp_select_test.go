package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleIDPSelect(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	// Create a test config
	config := Config{}
	config.Proxy.EntityID = "http://test.example.com/metadata"
	config.Proxy.CertificatePath = certPath
	config.Proxy.PrivateKeyPath = keyPath

	// Add test IDP
	config.IDP = []IDPConfig{
		{
			ID:              "idp1",
			EntityID:        "https://idp1.example.com/saml/metadata",
			SSOURL:          "https://idp1.example.com/saml/sso",
			CertificatePath: certPath,
		},
		{
			ID:              "idp2",
			EntityID:        "https://idp2.example.com/saml/metadata",
			SSOURL:          "https://idp2.example.com/saml/sso",
			CertificatePath: certPath,
		},
	}

	// Create SAML service providers
	providers, err := CreateServiceProviders(t.Context(), config)
	require.NoError(t, err)

	// Create SAML IDP
	idp, err := CreateProxyIDP(config)
	require.NoError(t, err)

	// Create a mock auth request
	authRequestID := "test-auth-request-id"
	idp.idpStorage.authRequestsLock.Lock()
	idp.idpStorage.authRequests[authRequestID] = &AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		IsDone:        false,
		RelayState:    "test-relay-state",
	}
	idp.idpStorage.authRequestsLock.Unlock()

	handler := handleIDPSelect(idp, providers)

	t.Run("Valid auth request ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_select?id="+authRequestID, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Select an Identity Provider")
		assert.Contains(t, w.Body.String(), "idp1")
		assert.Contains(t, w.Body.String(), "idp2")
		assert.Contains(t, w.Body.String(), "test-relay-state")

		// Check that the auth request ID cookie was set
		cookies := w.Result().Cookies()
		var authCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == cookieNameAuthRequestID {
				authCookie = cookie

				break
			}
		}
		assert.NotNil(t, authCookie)
		assert.Equal(t, authRequestID, authCookie.Value)
		assert.True(t, authCookie.HttpOnly)
		assert.Equal(t, "/", authCookie.Path)
	})

	t.Run("Without auth request ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_select", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Empty auth request ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_select?id=", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Invalid auth request ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_select?id=invalid-id", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Auth request without RelayState", func(t *testing.T) {
		// Create auth request without relay state
		authRequestID2 := "test-auth-request-id-2"
		idp.idpStorage.authRequestsLock.Lock()
		idp.idpStorage.authRequests[authRequestID2] = &AuthRequest{
			ID:            authRequestID2,
			ApplicationID: "test-app-id",
			IsDone:        false,
			RelayState:    "",
		}
		idp.idpStorage.authRequestsLock.Unlock()

		req := httptest.NewRequest(http.MethodGet, "/idp_select?id="+authRequestID2, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Select an Identity Provider")
		// Should not contain RelayState input when it's empty
		assert.NotContains(t, w.Body.String(), "id=\"RelayState\"")
	})
}
