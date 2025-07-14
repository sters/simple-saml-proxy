package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleIDPInitiated(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "GET request",
			method:         http.MethodGet,
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "IdP-Initiated flow not yet implemented\n",
		},
		{
			name:           "POST request",
			method:         http.MethodPost,
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "IdP-Initiated flow not yet implemented\n",
		},
		{
			name:           "PUT request",
			method:         http.MethodPut,
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "IdP-Initiated flow not yet implemented\n",
		},
		{
			name:           "DELETE request",
			method:         http.MethodDelete,
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "IdP-Initiated flow not yet implemented\n",
		},
		{
			name:           "HEAD request",
			method:         http.MethodHead,
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "", // HEAD requests don't return body
		},
		{
			name:           "OPTIONS request",
			method:         http.MethodOptions,
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "IdP-Initiated flow not yet implemented\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(tt.method, "/idp-initiated", nil)
			w := httptest.NewRecorder()

			// Call handler
			handleIDPInitiated(w, req)

			// Check response
			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.method != http.MethodHead {
				assert.Equal(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestHandleIDPInitiatedWithDifferentPaths(t *testing.T) {
	paths := []string{
		"/idp-initiated",
		"/idp-initiated/",
		"/idp-initiated/test",
		"/idp-initiated?param=value",
		"/idp-initiated#fragment",
	}

	for _, path := range paths {
		t.Run("Path: "+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			handleIDPInitiated(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
			assert.Equal(t, "IdP-Initiated flow not yet implemented\n", w.Body.String())
		})
	}
}

func TestHandleIDPInitiatedWithHeaders(t *testing.T) {
	// Test that the handler works correctly regardless of headers
	req := httptest.NewRequest(http.MethodGet, "/idp-initiated", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/xml")
	req.Header.Set("User-Agent", "Test-Agent")

	w := httptest.NewRecorder()

	handleIDPInitiated(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	assert.Equal(t, "IdP-Initiated flow not yet implemented\n", w.Body.String())
}

func TestHandleIDPInitiatedConcurrent(t *testing.T) {
	// Test concurrent requests to ensure thread safety
	done := make(chan bool, 10)

	for range 10 {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/idp-initiated", nil)
			w := httptest.NewRecorder()

			handleIDPInitiated(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
			assert.Equal(t, "IdP-Initiated flow not yet implemented\n", w.Body.String())

			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}
}
