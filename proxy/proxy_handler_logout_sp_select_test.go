package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleLogoutSPSelect(t *testing.T) {
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
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{
			EntityID: "https://sp1.example.com",
		},
		{
			EntityID: "https://sp2.example.com",
		},
	}

	// Create storage and IDP
	storage, err := saml.NewStorage(cfg)
	require.NoError(t, err)

	idp := &saml.IDP{
		IDPStorage: storage,
	}

	handler := handleLogoutSPSelect(idp, nil)

	tests := []struct {
		name               string
		method             string
		query              string
		expectedStatus     int
		expectedBodyChecks []string
		notExpectedBody    []string
	}{
		{
			name:           "GET request with valid context",
			method:         http.MethodGet,
			query:          "context=test-context-id",
			expectedStatus: http.StatusOK,
			expectedBodyChecks: []string{
				"Select Service Provider for Logout",
				"https://sp1.example.com",
				"https://sp2.example.com",
				"https://sp1.example.com",
				"https://sp2.example.com",
				`action="/logout_sp_selected"`,
			},
		},
		{
			name:           "GET request without context",
			method:         http.MethodGet,
			query:          "",
			expectedStatus: http.StatusOK,
			expectedBodyChecks: []string{
				"Select Service Provider for Logout",
			},
		},
		{
			name:           "POST request",
			method:         http.MethodPost,
			query:          "context=test",
			expectedStatus: http.StatusOK,
			expectedBodyChecks: []string{
				"Select Service Provider for Logout",
			},
		},
		{
			name:           "GET request with multiple context values",
			method:         http.MethodGet,
			query:          "context=ctx1&context=ctx2",
			expectedStatus: http.StatusOK,
			expectedBodyChecks: []string{
				"Select Service Provider for Logout",
			},
		},
		{
			name:           "GET request with special characters in context",
			method:         http.MethodGet,
			query:          "context=" + url.QueryEscape("<script>alert('xss')</script>"),
			expectedStatus: http.StatusOK,
			expectedBodyChecks: []string{
				"Select Service Provider for Logout",
			},
			notExpectedBody: []string{
				"<script>alert('xss')</script>", // Should not contain unescaped script
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/logout_sp_select?"+tt.query, nil)
			// Add the required logout context cookie
			req.AddCookie(&http.Cookie{
				Name:  "logout_context_id",
				Value: "test-logout-context",
			})
			w := httptest.NewRecorder()

			handler(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			body := w.Body.String()
			for _, expected := range tt.expectedBodyChecks {
				assert.Contains(t, body, expected, "Expected to find: %s", expected)
			}

			for _, notExpected := range tt.notExpectedBody {
				assert.NotContains(t, body, notExpected, "Should not contain: %s", notExpected)
			}
		})
	}
}

func TestHandleLogoutSPSelectWithNoAllowedSPs(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	// Create test configuration with no allowed SPs
	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath
	cfg.Proxy.AllowedSP = []config.SPConfig{} // Empty

	storage, err := saml.NewStorage(cfg)
	require.NoError(t, err)

	idp := &saml.IDP{
		IDPStorage: storage,
	}

	handler := handleLogoutSPSelect(idp, nil)

	req := httptest.NewRequest(http.MethodGet, "/logout_sp_select?context=test", nil)
	// Add the required logout context cookie
	req.AddCookie(&http.Cookie{
		Name:  "logout_context_id",
		Value: "test-logout-context",
	})
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body := w.Body.String()
	assert.Contains(t, body, "Select Service Provider for Logout")
	// When there are no SPs, the form is inside the {{range .SPs}} block, so no form is rendered
	assert.NotContains(t, body, "<form")                  // No form when no SPs
	assert.NotContains(t, body, "<li class=\"sp-item\">") // No SP items should be rendered
}

func TestHandleLogoutSPSelectHTMLRendering(t *testing.T) {
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
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{
			EntityID: "https://sp.example.com/saml?metadata&test=1",
		},
	}

	storage, err := saml.NewStorage(cfg)
	require.NoError(t, err)

	idp := &saml.IDP{
		IDPStorage: storage,
	}

	handler := handleLogoutSPSelect(idp, nil)

	req := httptest.NewRequest(http.MethodGet, "/logout_sp_select", nil)
	// Add the required logout context cookie
	req.AddCookie(&http.Cookie{
		Name:  "logout_context_id",
		Value: "test-logout-context",
	})
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))

	body := w.Body.String()
	// Check that HTML is well-formed
	assert.True(t, strings.HasPrefix(strings.TrimSpace(body), "<!DOCTYPE html>"))
	assert.Contains(t, body, "</html>")

	// Check that special characters in URLs are properly encoded
	assert.Contains(t, body, "https://sp.example.com/saml?metadata&amp;test=1")
}

func TestHandleLogoutSPSelectWithoutCookie(t *testing.T) {
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

	storage, err := saml.NewStorage(cfg)
	require.NoError(t, err)

	idp := &saml.IDP{
		IDPStorage: storage,
	}

	handler := handleLogoutSPSelect(idp, nil)

	// Create request without the required cookie
	req := httptest.NewRequest(http.MethodGet, "/logout_sp_select", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 400 Bad Request when cookie is missing
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "Invalid logout request\n", w.Body.String())
}
