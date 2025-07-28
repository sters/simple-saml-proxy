package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetSecureCookie(t *testing.T) {
	tests := []struct {
		name         string
		request      *http.Request
		cookieName   string
		cookieValue  string
		maxAge       int
		wantSecure   bool
		wantHTTPOnly bool
		wantPath     string
		wantMaxAge   int
	}{
		{
			name:         "HTTP request",
			request:      httptest.NewRequest(http.MethodGet, "http://example.com/test", nil),
			cookieName:   "test_cookie",
			cookieValue:  "test_value",
			maxAge:       300,
			wantSecure:   false,
			wantHTTPOnly: true,
			wantPath:     "/",
			wantMaxAge:   300,
		},
		{
			name:         "HTTPS request",
			request:      httptest.NewRequest(http.MethodGet, "https://example.com/test", nil),
			cookieName:   "secure_cookie",
			cookieValue:  "secure_value",
			maxAge:       600,
			wantSecure:   true,
			wantHTTPOnly: true,
			wantPath:     "/",
			wantMaxAge:   600,
		},
		{
			name: "Request with X-Forwarded-Proto header",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
				req.Header.Set("X-Forwarded-Proto", "https")

				return req
			}(),
			cookieName:   "forwarded_cookie",
			cookieValue:  "forwarded_value",
			maxAge:       -1,
			wantSecure:   true,
			wantHTTPOnly: true,
			wantPath:     "/",
			wantMaxAge:   -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create response recorder
			w := httptest.NewRecorder()

			// Set the cookie
			SetSecureCookie(w, tt.request, tt.cookieName, tt.cookieValue, tt.maxAge)

			// Get the cookies from the response
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1, "Expected exactly one cookie")

			cookie := cookies[0]
			assert.Equal(t, tt.cookieName, cookie.Name)
			assert.Equal(t, tt.cookieValue, cookie.Value)
			assert.Equal(t, tt.wantSecure, cookie.Secure)
			assert.Equal(t, tt.wantHTTPOnly, cookie.HttpOnly)
			assert.Equal(t, tt.wantPath, cookie.Path)
			assert.Equal(t, tt.wantMaxAge, cookie.MaxAge)
		})
	}
}
