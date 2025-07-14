package proxy

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSimulatedReadError = errors.New("simulated read error")

func TestRandomBytes(t *testing.T) {
	// Test that randomBytes returns the requested number of bytes
	result := randomBytes(10)
	assert.Len(t, result, 10)

	// Test that randomBytes returns different values on subsequent calls
	result1 := randomBytes(20)
	result2 := randomBytes(20)
	assert.Len(t, result1, 20)
	assert.Len(t, result2, 20)
	assert.NotEqual(t, result1, result2)

	// Test edge cases
	result = randomBytes(0)
	assert.Empty(t, result)

	result = randomBytes(1)
	assert.Len(t, result, 1)

	// Test with larger values
	result = randomBytes(100)
	assert.Len(t, result, 100)
}

func TestRandomBytes_Error(t *testing.T) {
	// Save original rand.Reader
	originalReader := rand.Reader
	defer func() {
		rand.Reader = originalReader
	}()

	// Replace with a reader that always fails
	rand.Reader = &errorReader{}

	// Test that randomBytes returns nil when rand.Reader fails
	result := randomBytes(10)
	assert.Nil(t, result)
}

// errorReader implements io.Reader but always returns an error.
type errorReader struct{}

func (e *errorReader) Read([]byte) (int, error) {
	return 0, errSimulatedReadError
}

func TestDeflateCompress(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Empty data",
			input:   []byte{},
			wantErr: false,
		},
		{
			name:    "Small data",
			input:   []byte("Hello, World!"),
			wantErr: false,
		},
		{
			name:    "Large data",
			input:   bytes.Repeat([]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. "), 1000),
			wantErr: false,
		},
		{
			name:    "Binary data",
			input:   []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			wantErr: false,
		},
		{
			name:    "Data with null bytes",
			input:   []byte("Hello\x00World\x00!"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := deflateCompress(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, compressed)

				// Verify we can decompress back to original
				reader := flate.NewReader(bytes.NewReader(compressed))
				defer reader.Close()

				var buf bytes.Buffer
				_, err = buf.ReadFrom(reader)
				require.NoError(t, err)

				assert.Equal(t, tt.input, buf.Bytes())
			}
		})
	}
}

func TestDeflateCompress_Efficiency(t *testing.T) {
	// Test that compression actually reduces size for repetitive data
	repetitiveData := bytes.Repeat([]byte("AAAAAAAAAA"), 1000) // 10,000 bytes
	compressed, err := deflateCompress(repetitiveData)
	require.NoError(t, err)

	// Compressed size should be significantly smaller
	assert.Less(t, len(compressed), len(repetitiveData)/10)
	t.Logf("Original size: %d, Compressed size: %d", len(repetitiveData), len(compressed))
}

func TestDeflateCompress_ErrorPaths(t *testing.T) {
	// Test the scenario where deflateCompress might encounter an issue
	// Due to the nature of flate.NewWriter and the compression process,
	// it's difficult to trigger actual errors without complex setup.
	// However, we can test edge cases and ensure the function handles them properly.

	// Test with nil input (should work fine)
	compressed, err := deflateCompress(nil)
	require.NoError(t, err)
	assert.NotNil(t, compressed)

	// Test with extremely large data that might cause memory issues
	// This is more of a stress test than an error test
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	compressed, err = deflateCompress(largeData)
	require.NoError(t, err)
	assert.NotNil(t, compressed)

	// Verify decompression works
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(reader)
	require.NoError(t, err)
	assert.Equal(t, largeData, buf.Bytes())

	// Test compression consistency - same input should produce same output
	data := []byte("test data for compression consistency")
	compressed1, err1 := deflateCompress(data)
	compressed2, err2 := deflateCompress(data)
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, compressed1, compressed2)
}

func TestIsSecureCookie(t *testing.T) {
	tests := []struct {
		name     string
		request  func() *http.Request
		expected bool
	}{
		{
			name: "HTTPS request",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
				req.TLS = &tls.ConnectionState{}

				return req
			},
			expected: true,
		},
		{
			name: "HTTP request",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			},
			expected: false,
		},
		{
			name: "HTTP with X-Forwarded-Proto https",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
				req.Header.Set("X-Forwarded-Proto", "https")

				return req
			},
			expected: true,
		},
		{
			name: "HTTP with X-Forwarded-Proto http",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
				req.Header.Set("X-Forwarded-Proto", "http")

				return req
			},
			expected: false,
		},
		{
			name: "HTTP with X-Forwarded-Proto mixed case",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
				req.Header.Set("X-Forwarded-Proto", "HTTPS")

				return req
			},
			expected: false, // Header check is case-sensitive
		},
		{
			name: "HTTPS with X-Forwarded-Proto http (TLS takes precedence)",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
				req.TLS = &tls.ConnectionState{}
				req.Header.Set("X-Forwarded-Proto", "http")

				return req
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSecureCookie(tt.request())
			assert.Equal(t, tt.expected, result)
		})
	}
}
