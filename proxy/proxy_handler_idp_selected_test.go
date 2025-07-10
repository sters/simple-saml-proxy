package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleIDPSelected(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	// Create a test config
	cfg := config.Config{}
	cfg.Proxy.EntityID = "http://test.example.com/metadata"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Add test IDP
	cfg.IDP = []config.IDPConfig{
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
	providers, err := saml.CreateServiceProviders(t.Context(), cfg)
	require.NoError(t, err)

	// Create SAML IDP
	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	// Create a mock auth request
	authRequestID := "test-auth-request-id"
	idp.IDPStorage.AddAuthRequestForTesting(&saml.AuthRequest{
		ID:            authRequestID,
		ApplicationID: "test-app-id",
		IsDone:        false,
		RelayState:    "test-relay-state",
	})

	handler := handleIDPSelected(idp, providers)

	t.Run("Valid parameters", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_selected?idpID=idp1", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: authRequestID,
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		redirectURL := w.Header().Get("Location")
		assert.Contains(t, redirectURL, "https://idp1.example.com/saml/sso")

		// Check that the IDP ID cookie was set
		cookies := w.Result().Cookies()
		var idpCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == cookieNameIDPID {
				idpCookie = cookie

				break
			}
		}
		assert.NotNil(t, idpCookie)
		assert.Equal(t, "idp1", idpCookie.Value)
		assert.True(t, idpCookie.HttpOnly)
		assert.Equal(t, "/", idpCookie.Path)
	})

	t.Run("Different IdP selection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_selected?idpID=idp2", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: authRequestID,
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		redirectURL := w.Header().Get("Location")
		assert.Contains(t, redirectURL, "https://idp2.example.com/saml/sso")
	})

	t.Run("Without auth request ID cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_selected?idpID=idp1", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Empty auth request ID cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_selected?idpID=idp1", nil)
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
		req := httptest.NewRequest(http.MethodGet, "/idp_selected?idpID=idp1", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: "invalid-id",
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("Invalid IDP ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/idp_selected?idpID=invalid-idp", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: authRequestID,
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid IDP ID")
	})

	t.Run("Auth request without RelayState", func(t *testing.T) {
		// Create auth request without relay state
		authRequestID2 := "test-auth-request-id-2"
		idp.IDPStorage.AddAuthRequestForTesting(&saml.AuthRequest{
			ID:            authRequestID2,
			ApplicationID: "test-app-id",
			IsDone:        false,
			RelayState:    "",
		})

		req := httptest.NewRequest(http.MethodGet, "/idp_selected?idpID=idp1", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieNameAuthRequestID,
			Value: authRequestID2,
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		// Should generate a new RelayState when original is empty
		redirectURL := w.Header().Get("Location")
		assert.Contains(t, redirectURL, "https://idp1.example.com/saml/sso")
	})
}
