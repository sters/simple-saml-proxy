package testutil

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
)

// ptrString returns a pointer to a string.
func ptrString(s string) *string {
	return &s
}

// ptrBool returns a pointer to a bool.
func ptrBool(b bool) *bool {
	return &b
}

// GenerateTestCertificate creates a test certificate and private key.
func GenerateTestCertificate(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// GenerateTestCertificatePEM creates a test certificate and private key in PEM format.
func GenerateTestCertificatePEM(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()

	cert, key := GenerateTestCertificate(t, commonName)

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Encode private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return certPEM, keyPEM
}

// CreateTestLogoutRequest creates a basic SAML logout request for testing.
func CreateTestLogoutRequest(issuer, nameID string) *crewjamsaml.LogoutRequest {
	return CreateTestLogoutRequestWithTime(issuer, nameID, time.Now())
}

// CreateTestLogoutRequestWithTime creates a SAML logout request with specific issue instant.
func CreateTestLogoutRequestWithTime(issuer, nameID string, issueInstant time.Time) *crewjamsaml.LogoutRequest {
	return &crewjamsaml.LogoutRequest{
		ID:           "test-logout-request-id",
		Version:      "2.0",
		IssueInstant: issueInstant,
		Destination:  "https://proxy.example.com/saml/slo",
		Issuer: &crewjamsaml.Issuer{
			Value: issuer,
		},
		NameID: &crewjamsaml.NameID{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			Value:  nameID,
		},
		SessionIndex: &crewjamsaml.SessionIndex{
			Value: "test-session-index",
		},
	}
}

// CreateTestAuthRequest creates a basic SAML authentication request for testing.
func CreateTestAuthRequest(issuer string) *crewjamsaml.AuthnRequest {
	return &crewjamsaml.AuthnRequest{
		ID:           "test-auth-request-id",
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  "https://proxy.example.com/saml/sso",
		Issuer: &crewjamsaml.Issuer{
			Value: issuer,
		},
		NameIDPolicy: &crewjamsaml.NameIDPolicy{
			Format:      ptrString("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
			AllowCreate: ptrBool(true),
		},
	}
}

// CompressData compresses data using deflate algorithm (for SAML HTTP-Redirect binding).
func CompressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to create deflate writer: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write compressed data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close deflate writer: %w", err)
	}

	return buf.Bytes(), nil
}

// Base64EncodeSAML encodes SAML data to base64 (standard encoding).
func Base64EncodeSAML(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64DecodeSAML decodes base64 encoded SAML data.
func Base64DecodeSAML(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	return data, nil
}

// CreateTestHTTPRequest creates a test HTTP request with common SAML parameters.
func CreateTestHTTPRequest(method, path string, params map[string]string) *http.Request {
	req := httptest.NewRequest(method, path, nil)

	if params != nil {
		q := req.URL.Query()
		for key, value := range params {
			q.Set(key, value)
		}
		req.URL.RawQuery = q.Encode()
	}

	return req
}

// CreateTestRecorder creates a new httptest.ResponseRecorder.
func CreateTestRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

// AssertHTTPStatus asserts that the HTTP response has the expected status code.
func AssertHTTPStatus(t *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int) {
	t.Helper()
	require.Equal(t, expectedStatus, recorder.Code, "unexpected HTTP status code: %s", recorder.Body.String())
}

// AssertContains asserts that the response body contains the expected string.
func AssertContains(t *testing.T, recorder *httptest.ResponseRecorder, expected string) {
	t.Helper()
	require.Contains(t, recorder.Body.String(), expected)
}

// AssertNotContains asserts that the response body does not contain the string.
func AssertNotContains(t *testing.T, recorder *httptest.ResponseRecorder, unexpected string) {
	t.Helper()
	require.NotContains(t, recorder.Body.String(), unexpected)
}
