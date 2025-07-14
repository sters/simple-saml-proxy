package saml

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errMockClientNotConfigured  = errors.New("mock client not configured")
	errNetworkConnectionRefused = errors.New("network error: connection refused")
)

// Helper function to create config with metadata settings.
func createConfigWithMetadata(maxRetries int, initialDelay, maxDelay time.Duration) config.Config {
	cfg := config.Config{}
	cfg.Metadata.MaxRetries = maxRetries
	cfg.Metadata.InitialDelay = initialDelay
	cfg.Metadata.MaxDelay = maxDelay

	return cfg
}

//nolint:maintidx // Test function needs to be complex to cover all retry scenarios and edge cases
func TestReadMetadataFromURLWithRetry(t *testing.T) {
	validMetadata := `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://test.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	tests := []struct {
		name          string
		setupServer   func() *httptest.Server
		config        config.Config
		expectedError string
		checkResult   func(t *testing.T, metadata []byte)
		timeout       time.Duration
	}{
		{
			name: "Success on first attempt",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(validMetadata))
				}))
			},
			config: config.Config{},
			checkResult: func(t *testing.T, metadata []byte) {
				t.Helper()
				assert.Equal(t, validMetadata, string(metadata))
			},
		},
		{
			name: "Success after 2 retries",
			setupServer: func() *httptest.Server {
				var attempts int32

				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					attempt := atomic.AddInt32(&attempts, 1)
					if attempt < 3 {
						w.WriteHeader(http.StatusServiceUnavailable)

						return
					}
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(validMetadata))
				}))
			},
			config: createConfigWithMetadata(3, 10*time.Millisecond, 50*time.Millisecond),
			checkResult: func(t *testing.T, metadata []byte) {
				t.Helper()
				assert.Equal(t, validMetadata, string(metadata))
			},
		},
		{
			name: "Failure after max retries",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("Internal Server Error"))
				}))
			},
			config: createConfigWithMetadata(
				2, 5*time.Millisecond, 20*time.Millisecond),
			expectedError: "failed to read metadata after 3 attempts",
		},
		{
			name: "Context cancellation during retry",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					// Always fail to trigger retries
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
			},
			config:        createConfigWithMetadata(5, 100*time.Millisecond, 30*time.Second),
			expectedError: "context cancelled while retrying metadata read",
			timeout:       50 * time.Millisecond, // Cancel before first retry
		},
		{
			name: "Different HTTP errors on each attempt",
			setupServer: func() *httptest.Server {
				var attempts int32

				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					attempt := atomic.AddInt32(&attempts, 1)
					switch attempt {
					case 1:
						w.WriteHeader(http.StatusTooManyRequests)
					case 2:
						w.WriteHeader(http.StatusBadGateway)
					case 3:
						w.WriteHeader(http.StatusGatewayTimeout)
					default:
						w.WriteHeader(http.StatusServiceUnavailable)
					}
				}))
			},
			config:        createConfigWithMetadata(3, 5*time.Millisecond, 30*time.Second),
			expectedError: "failed to read metadata after 4 attempts",
		},
		{
			name: "Default retry configuration",
			setupServer: func() *httptest.Server {
				var attempts int32

				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					attempt := atomic.AddInt32(&attempts, 1)
					if attempt == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)

						return
					}
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(validMetadata))
				}))
			},
			config: config.Config{}, // Empty config to test defaults
			checkResult: func(t *testing.T, metadata []byte) {
				t.Helper()
				assert.Equal(t, validMetadata, string(metadata))
			},
			timeout: 3 * time.Second, // Allow time for default delay
		},
		{
			name: "Exponential backoff reaches max delay",
			setupServer: func() *httptest.Server {
				var attempts int32

				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					attempt := atomic.AddInt32(&attempts, 1)
					if attempt < 5 {
						w.WriteHeader(http.StatusServiceUnavailable)

						return
					}
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(validMetadata))
				}))
			},
			config: createConfigWithMetadata(5, 10*time.Millisecond, 30*time.Millisecond),
			checkResult: func(t *testing.T, metadata []byte) {
				t.Helper()
				assert.Equal(t, validMetadata, string(metadata))
			},
		},
		{
			name: "Invalid URL",
			setupServer: func() *httptest.Server {
				// Return a dummy server, but we'll use an invalid URL
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
			},
			config:        createConfigWithMetadata(1, 5*time.Millisecond, 30*time.Second),
			expectedError: "failed to read metadata after 2 attempts",
		},
		{
			name: "Empty response body",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusOK)
					// Don't write any body
				}))
			},
			config: config.Config{},
			checkResult: func(t *testing.T, metadata []byte) {
				t.Helper()
				assert.Empty(t, metadata)
			},
		},
		{
			name: "Large metadata response",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusOK)
					// Write a large metadata response
					largeMetadata := `<?xml version="1.0" encoding="UTF-8"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://test.example.com">`
					for range 1000 {
						largeMetadata += `<ContactPerson contactType="technical"><GivenName>Test</GivenName><SurName>User</SurName><EmailAddress>test@example.com</EmailAddress></ContactPerson>`
					}
					largeMetadata += `</EntityDescriptor>`
					_, _ = w.Write([]byte(largeMetadata))
				}))
			},
			config: config.Config{},
			checkResult: func(t *testing.T, metadata []byte) {
				t.Helper()
				assert.Contains(t, string(metadata), "EntityDescriptor")
				assert.Greater(t, len(metadata), 100000) // Should be large
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			// Use the server URL unless testing invalid URL
			metadataURL := server.URL + "/metadata"
			if tt.name == "Invalid URL" {
				metadataURL = "http://[invalid-url]]/metadata"
			}

			ctx := t.Context()
			if tt.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.timeout)
				defer cancel()
			}

			client := &http.Client{
				Timeout: 5 * time.Second,
			}

			metadata, err := ReadMetadataFromURLWithRetry(ctx, client, metadataURL, tt.config)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, metadata)
				}
			}
		})
	}
}

func TestReadMetadataFromURLWithRetry_ConcurrentRequests(t *testing.T) {
	// Test that multiple concurrent requests work correctly
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always succeed to test concurrent access
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><EntityDescriptor/>`))
		requestCount.Add(1)
	}))
	defer server.Close()

	cfg := createConfigWithMetadata(2, 10*time.Millisecond, 30*time.Second)

	// Run multiple concurrent requests
	const numRequests = 5
	errors := make(chan error, numRequests)
	results := make(chan []byte, numRequests)

	for range numRequests {
		go func() {
			client := &http.Client{Timeout: 5 * time.Second}
			metadata, err := ReadMetadataFromURLWithRetry(t.Context(), client, server.URL+"/metadata", cfg)
			if err != nil {
				errors <- err
			} else {
				results <- metadata
			}
		}()
	}

	// Collect results
	successCount := 0
	errorCount := 0
	for range numRequests {
		select {
		case err := <-errors:
			t.Errorf("Unexpected error: %v", err)
			errorCount++
		case result := <-results:
			assert.NotEmpty(t, result)
			successCount++
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	assert.Equal(t, numRequests, successCount)
	assert.Equal(t, 0, errorCount)

	// Ensure at least numRequests were made (could be more due to retries)
	assert.GreaterOrEqual(t, int(requestCount.Load()), numRequests)
}

// MockHTTPClient is a mock implementation of http.Client for testing edge cases.
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}

	return nil, errMockClientNotConfigured
}

func TestReadMetadataFromURLWithRetry_HTTPClientError(t *testing.T) {
	// Test direct HTTP client errors (network issues, etc.)
	cfg := createConfigWithMetadata(1, 5*time.Millisecond, 30*time.Second)

	// Create a client that always fails
	client := &http.Client{
		Transport: &failingTransport{},
		Timeout:   1 * time.Second,
	}

	ctx := t.Context()
	metadata, err := ReadMetadataFromURLWithRetry(ctx, client, "https://example.com/metadata", cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read metadata after 2 attempts")
	assert.Nil(t, metadata)
}

type failingTransport struct{}

func (f *failingTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errNetworkConnectionRefused
}
