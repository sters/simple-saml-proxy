package proxy

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractIssuerFromSAMLRequest(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid compressed SAML request",
			input: func() string {
				authnRequest := &crewjamsaml.AuthnRequest{
					XMLName: xml.Name{
						Space: "urn:oasis:names:tc:SAML:2.0:protocol",
						Local: "AuthnRequest",
					},
					ID:      "_test-request-id",
					Version: "2.0",
					Issuer: &crewjamsaml.Issuer{
						Value: "https://sp.example.com",
					},
				}
				xmlBytes, _ := xml.Marshal(authnRequest)
				var compressed bytes.Buffer
				writer, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
				_, _ = writer.Write(xmlBytes)
				_ = writer.Close()
				encoded := base64.StdEncoding.EncodeToString(compressed.Bytes())

				return url.QueryEscape(encoded)
			}(),
			want:    "https://sp.example.com",
			wantErr: false,
		},
		{
			name: "Valid uncompressed SAML request",
			input: func() string {
				authnRequest := &crewjamsaml.AuthnRequest{
					XMLName: xml.Name{
						Space: "urn:oasis:names:tc:SAML:2.0:protocol",
						Local: "AuthnRequest",
					},
					ID:      "_test-request-id",
					Version: "2.0",
					Issuer: &crewjamsaml.Issuer{
						Value: "https://sp2.example.com",
					},
				}
				xmlBytes, _ := xml.Marshal(authnRequest)
				encoded := base64.StdEncoding.EncodeToString(xmlBytes)

				return url.QueryEscape(encoded)
			}(),
			want:    "https://sp2.example.com",
			wantErr: false,
		},
		{
			name: "SAML request without issuer",
			input: func() string {
				authnRequest := &crewjamsaml.AuthnRequest{
					XMLName: xml.Name{
						Space: "urn:oasis:names:tc:SAML:2.0:protocol",
						Local: "AuthnRequest",
					},
					ID:      "_test-request-id",
					Version: "2.0",
				}
				xmlBytes, _ := xml.Marshal(authnRequest)
				var compressed bytes.Buffer
				writer, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
				_, _ = writer.Write(xmlBytes)
				_ = writer.Close()
				encoded := base64.StdEncoding.EncodeToString(compressed.Bytes())

				return url.QueryEscape(encoded)
			}(),
			want:    "",
			wantErr: true,
			errMsg:  "no issuer in SAML request",
		},
		{
			name:    "Invalid URL encoding",
			input:   "%%invalid%%",
			want:    "",
			wantErr: true,
			errMsg:  "failed to URL decode",
		},
		{
			name:    "Invalid base64",
			input:   url.QueryEscape("!!!invalid-base64!!!"),
			want:    "",
			wantErr: true,
			errMsg:  "failed to base64 decode",
		},
		{
			name:    "Invalid XML",
			input:   url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<invalid>not a saml request</invalid>"))),
			want:    "",
			wantErr: true,
			errMsg:  "failed to unmarshal SAML request",
		},
		{
			name:    "Corrupted compressed data",
			input:   url.QueryEscape(base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF, 0xFF})),
			want:    "",
			wantErr: true,
			errMsg:  "failed to unmarshal SAML request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractIssuerFromSAMLRequest(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestDecodeDeflatedSAMLRequest(t *testing.T) {
	originalData := []byte("This is test data for SAML request compression")

	// Create properly compressed data
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = writer.Write(originalData)
	require.NoError(t, err)
	err = writer.Close()
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "Valid compressed data",
			input:   compressed.Bytes(),
			want:    originalData,
			wantErr: false,
		},
		{
			name:    "Invalid compressed data",
			input:   []byte{0xFF, 0xFF, 0xFF, 0xFF},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Empty data",
			input:   []byte{},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeDeflatedSAMLRequest(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestDecodeDeflatedSAMLRequest_LargeData(t *testing.T) {
	// Create data larger than 10MB limit
	largeData := make([]byte, 11*1024*1024) // 11MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Compress the large data
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	require.NoError(t, err)
	_, err = writer.Write(largeData)
	require.NoError(t, err)
	err = writer.Close()
	require.NoError(t, err)

	// Try to decompress - should read up to the limit
	result, err := decodeDeflatedSAMLRequest(compressed.Bytes())
	require.NoError(t, err)
	// Result should be truncated to 10MB
	assert.LessOrEqual(t, len(result), 10*1024*1024)
}

func TestRespondWithSAMLError(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	tests := []struct {
		name          string
		issuerID      string
		statusCode    string
		statusMessage string
		checkResponse func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:          "Basic error response",
			issuerID:      "https://sp.example.com",
			statusCode:    "RequestDenied",
			statusMessage: "Unauthorized service provider",
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusForbidden, w.Code)
				body := w.Body.String()
				assert.Contains(t, body, "Access Denied")
				assert.Contains(t, body, "https://sp.example.com")
				assert.Contains(t, body, "RequestDenied")
				assert.Contains(t, body, "Unauthorized service provider")
				assert.Contains(t, body, "<!DOCTYPE html>")
			},
		},
		{
			name:          "Error with special characters in issuer",
			issuerID:      "https://sp.example.com/saml?test=1&foo=bar",
			statusCode:    "RequestDenied",
			statusMessage: "Access denied",
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusForbidden, w.Code)
				body := w.Body.String()
				// Check that special characters are HTML-escaped
				assert.Contains(t, body, "https://sp.example.com/saml?test=1&amp;foo=bar")
			},
		},
		{
			name:          "Error with XSS attempt in issuer",
			issuerID:      "<script>alert('xss')</script>",
			statusCode:    "RequestDenied",
			statusMessage: "Invalid request",
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusForbidden, w.Code)
				body := w.Body.String()
				// The HTML should be escaped
				assert.Contains(t, body, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;")
				assert.NotContains(t, body, "<script>alert('xss')</script>")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sso", nil)
			w := httptest.NewRecorder()

			respondWithSAMLError(w, req, idp, tt.issuerID, tt.statusCode, tt.statusMessage)

			tt.checkResponse(t, w)
		})
	}
}

func TestHandleSSO_NoSAMLRequest(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	handler := handleSSO(idp)

	// Test with no SAML request - should pass through to original handler
	req := httptest.NewRequest(http.MethodGet, "/sso", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// The zitadel library will handle this case
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandleSSO_InvalidSAMLRequest(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := saml.GenerateTestCertificate(t)
	defer func() {
		if certPath != "" {
			_ = os.RemoveAll(filepath.Dir(certPath))
		}
	}()

	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	idp, err := saml.CreateProxyIDP(cfg)
	require.NoError(t, err)

	handler := handleSSO(idp)

	// Test with invalid SAML request - should pass through to original handler
	req := httptest.NewRequest(http.MethodGet, "/sso?SAMLRequest="+url.QueryEscape("invalid-base64"), nil)
	w := httptest.NewRecorder()

	handler(w, req)

	// The handler logs the error and passes through to the original handler
	// which will handle the invalid request
	resp := w.Result()
	defer resp.Body.Close()

	// The exact status depends on how the zitadel library handles invalid requests
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
}
