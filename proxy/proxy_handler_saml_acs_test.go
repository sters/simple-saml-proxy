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

func TestHandleSAMLACS(t *testing.T) {
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
	}
	idp.idpStorage.authRequestsLock.Unlock()

	handler := handleSAMLACS(idp, providers)

	t.Run("Without auth request ID cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Empty auth request ID cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: "",
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Invalid auth request ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: "invalid-id",
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Without IDP ID cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: authRequestID,
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Empty IDP ID cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: authRequestID,
		})
		req.AddCookie(&http.Cookie{
			Name:  cookieNameIDPID,
			Value: "",
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Invalid IDP ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: authRequestID,
		})
		req.AddCookie(&http.Cookie{
			Name:  cookieNameIDPID,
			Value: "invalid-idp",
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid IDP ID")
	})

	t.Run("Valid cookies but no SAML response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: authRequestID,
		})
		req.AddCookie(&http.Cookie{
			Name:  cookieNameIDPID,
			Value: "idp1",
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Without a valid SAML response, the parser will fail
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})
}
