package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandlePing(t *testing.T) {
	// Test the ping handler
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := httptest.NewRecorder()
	handlePing(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "pong", w.Body.String())
}

// mockResponseWriter that always fails on Write.
type failingResponseWriter struct {
	http.ResponseWriter
	header http.Header
}

func (f *failingResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}

	return f.header
}

func (f *failingResponseWriter) Write([]byte) (int, error) {
	return 0, http.ErrNotSupported
}

func (f *failingResponseWriter) WriteHeader(_ int) {
	// Do nothing
}

func TestHandlePing_WriteError(_ *testing.T) {
	// Test the ping handler with a failing response writer
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := &failingResponseWriter{}

	// This should not panic, just log the error
	handlePing(w, req)

	// The function should handle the error gracefully
	// We can't easily test the log output, but we ensure it doesn't panic
}
