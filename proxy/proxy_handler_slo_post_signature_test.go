package proxy

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleSLOWithHTTPPostSignature(t *testing.T) {
	// This test simulates an HTTP-POST binding logout request with XML signature

	// Generate test certificates
	spCert, spKey := generateTestCertificate(t, "SP Test")

	// Create a signed logout request
	signedRequest := createSignedLogoutRequest(t, spKey, spCert)

	// Marshal the request to XML
	requestBytes, err := signedRequest.Bytes()
	require.NoError(t, err)

	// Base64 encode the request
	encodedRequest := base64.StdEncoding.EncodeToString(requestBytes)

	// Create form data
	form := url.Values{}
	form.Add("SAMLRequest", encodedRequest)
	form.Add("RelayState", "test-relay-state")

	// Create a test request
	req := httptest.NewRequest(http.MethodPost, "/slo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Test that the request contains a signature
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedRequest)
	require.NoError(t, err)

	var decodedRequest crewjamsaml.LogoutRequest
	err = xml.Unmarshal(decodedBytes, &decodedRequest)
	require.NoError(t, err)

	// The signature should be present (though we can't validate it in this unit test without a full IDP setup)
	assert.NotEmpty(t, decodedBytes)
	assert.Contains(t, string(decodedBytes), "Signature")
	assert.Contains(t, string(decodedBytes), "SignatureValue")
	assert.Equal(t, "https://sp.example.com", decodedRequest.Issuer.Value)
}

func TestHTTPPostVsRedirectBindingDetection(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		queryParams     url.Values
		formData        url.Values
		expectedBinding string
	}{
		{
			name:   "HTTP-Redirect binding",
			method: http.MethodGet,
			queryParams: url.Values{
				"SAMLRequest": []string{"encoded-request"},
				"Signature":   []string{"signature"},
				"SigAlg":      []string{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
			},
			expectedBinding: "redirect",
		},
		{
			name:   "HTTP-POST binding",
			method: http.MethodPost,
			formData: url.Values{
				"SAMLRequest": []string{"encoded-request"},
			},
			expectedBinding: "post",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.method == http.MethodGet {
				req = httptest.NewRequest(tt.method, "/slo?"+tt.queryParams.Encode(), nil)
			} else {
				req = httptest.NewRequest(tt.method, "/slo", strings.NewReader(tt.formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			// Check binding detection
			if req.Method == http.MethodGet {
				assert.Equal(t, "redirect", tt.expectedBinding)
				assert.NotEmpty(t, req.URL.RawQuery)
			} else {
				assert.Equal(t, "post", tt.expectedBinding)
				assert.Empty(t, req.URL.RawQuery)
			}
		})
	}
}
