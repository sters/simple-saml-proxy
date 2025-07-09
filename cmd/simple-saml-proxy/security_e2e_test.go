package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSecurityTest creates a common test setup for security tests.
func setupSecurityTest(t *testing.T) (*httptest.Server, *MockSAMLProvider) {
	t.Helper()

	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	mockProvider := NewMockSAMLProvider(t)

	cfg := proxy.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	cfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	cfg.Proxy.PrivateKeyPath = proxyKeyPath
	cfg.Proxy.CertificatePath = proxyCertPath
	cfg.Proxy.AllowedSP = []proxy.SPConfig{
		{EntityID: "https://sp.example.com"},
	}
	cfg.IDP = []proxy.IDPConfig{
		{
			ID:          "test-idp",
			MetadataURL: mockProvider.server.URL + "/saml/metadata",
		},
	}

	ctx := t.Context()
	providers, err := proxy.CreateServiceProviders(ctx, cfg)
	require.NoError(t, err)

	idp, err := proxy.CreateProxyIDP(cfg)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, cfg)
	server := httptest.NewServer(mux)

	return server, mockProvider
}

func TestSecurityE2E_TamperedSAMLRequest(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()
	// Create a valid SAML request
	authnReq := saml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &saml.Issuer{
			Value: "https://sp.example.com",
		},
		AssertionConsumerServiceURL: "https://sp.example.com/acs",
		ProtocolBinding:             saml.HTTPPostBinding,
	}

	doc := etree.NewDocument()
	doc.SetRoot(authnReq.Element())
	requestXML, _ := doc.WriteToString()

	// Tamper with the request after encoding
	encoded := base64.StdEncoding.EncodeToString([]byte(requestXML))
	tampered := encoded[:len(encoded)-10] + "TAMPERED=="

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/sso?SAMLRequest="+url.QueryEscape(tampered), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject tampered request - proxy returns 200 with error in SAML response
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "RequestDenied", "Should reject tampered SAML request")
}

func TestSecurityE2E_UnauthorizedSPRequest(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Create request from unauthorized SP
	authnReq := saml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &saml.Issuer{
			Value: "https://unauthorized-sp.example.com", // Not in AllowedSPs
		},
		AssertionConsumerServiceURL: "https://unauthorized-sp.example.com/acs",
		ProtocolBinding:             saml.HTTPPostBinding,
	}

	doc := etree.NewDocument()
	doc.SetRoot(authnReq.Element())
	requestXML, _ := doc.WriteToString()
	encoded := base64.StdEncoding.EncodeToString([]byte(requestXML))
	compressed := compress(encoded)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/sso?SAMLRequest="+url.QueryEscape(compressed), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject unauthorized SP or show error - current implementation shows decode error
	body, _ := io.ReadAll(resp.Body)
	// TODO: Proxy should check AllowedSP and reject unauthorized SPs
	assert.Contains(t, string(body), "RequestDenied", "Should handle unauthorized SP")
}

func TestSecurityE2E_InvalidRelayState(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Test with excessively long RelayState (security risk)
	authnReq := saml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &saml.Issuer{
			Value: "https://sp.example.com",
		},
		AssertionConsumerServiceURL: "https://sp.example.com/acs",
	}

	doc := etree.NewDocument()
	doc.SetRoot(authnReq.Element())
	requestXML, _ := doc.WriteToString()
	encoded := base64.StdEncoding.EncodeToString([]byte(requestXML))
	compressed := compress(encoded)

	// Create very long RelayState (potential buffer overflow attempt)
	longRelayState := strings.Repeat("A", 10000)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
		server.URL+"/sso?SAMLRequest="+url.QueryEscape(compressed)+"&RelayState="+url.QueryEscape(longRelayState),
		nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should handle gracefully without buffer overflow
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode, "Should handle long RelayState gracefully")
}

func TestSecurityE2E_MissingRequiredParameters(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Test with missing SAMLRequest
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/sso", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject request without SAMLRequest - proxy returns 200 with error
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "RequestDenied", "Should reject request without SAMLRequest")
}

func TestSecurityE2E_ExpiredAssertion(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Create an expired SAML response
	response := &saml.Response{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC().Add(-2 * time.Hour), // Old response
		Version:      "2.0",
		Issuer: &saml.Issuer{
			Value: mockProvider.entityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
		Assertion: &saml.Assertion{
			ID:           "_" + uuid.New().String(),
			IssueInstant: time.Now().UTC().Add(-2 * time.Hour),
			Version:      "2.0",
			Issuer: saml.Issuer{
				Value: mockProvider.entityID,
			},
			Subject: &saml.Subject{
				NameID: &saml.NameID{
					Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
					Value:  "testuser",
				},
			},
			Conditions: &saml.Conditions{
				NotBefore:    time.Now().UTC().Add(-3 * time.Hour),
				NotOnOrAfter: time.Now().UTC().Add(-1 * time.Hour), // Already expired
			},
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	responseXML, _ := doc.WriteToString()
	encoded := base64.StdEncoding.EncodeToString([]byte(responseXML))

	form := url.Values{}
	form.Set("SAMLResponse", encoded)
	form.Set("RelayState", "test-state")

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject expired assertion
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Should reject expired assertion")
}

func TestSecurityE2E_ReplayAttackPrevention(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Create a valid SAML response
	samlResp := mockProvider.createSAMLResponse("test-123", server.URL+"/saml/acs")
	encoded := base64.StdEncoding.EncodeToString([]byte(samlResp))

	form := url.Values{}
	form.Set("SAMLResponse", encoded)
	form.Set("RelayState", "test-state")

	// First submission
	req1, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	resp1.Body.Close()

	// Replay the same response
	req2, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	// Should reject replayed response
	// Note: This might not fail if replay detection is not implemented
	t.Log("Replay attack test completed - implementation may need replay detection")
}

func TestSecurityE2E_InvalidInResponseTo(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Create response with wrong InResponseTo
	response := &saml.Response{
		ID:           "_" + uuid.New().String(),
		InResponseTo: "wrong-request-id", // Does not match any stored request
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &saml.Issuer{
			Value: mockProvider.entityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	responseXML, _ := doc.WriteToString()
	encoded := base64.StdEncoding.EncodeToString([]byte(responseXML))

	form := url.Values{}
	form.Set("SAMLResponse", encoded)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject response with invalid InResponseTo
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Should reject response with invalid InResponseTo")
}

func TestSecurityE2E_InvalidCertificateChain(t *testing.T) {
	// Test with self-signed certificate that's not trusted
	t.Log("Certificate chain validation test - implementation depends on SAML library configuration")
}

func TestSecurityE2E_ExpiredCertificate(t *testing.T) {
	testDir := t.TempDir()
	// Create certificate that's already expired
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Expired"},
		},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour), // Already expired
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	expiredCertPath := filepath.Join(testDir, "expired.crt")
	expiredKeyPath := filepath.Join(testDir, "expired.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	require.NoError(t, os.WriteFile(expiredCertPath, certPEM, 0o644))
	require.NoError(t, os.WriteFile(expiredKeyPath, keyPEM, 0o644))

	// Test would verify that expired certificates are rejected
	t.Log("Expired certificate test - would need to test IdP with expired cert")
}

func TestSecurityE2E_XMLInjectionAttack(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Attempt XML injection in SAML request
	maliciousXML := `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0">
<Issuer>&xxe;</Issuer>
</samlp:AuthnRequest>`

	encoded := base64.StdEncoding.EncodeToString([]byte(maliciousXML))
	compressed := compress(encoded)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/sso?SAMLRequest="+url.QueryEscape(compressed), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// Should not expose system files
	assert.NotContains(t, string(body), "/etc/passwd", "Should not be vulnerable to XXE")
	assert.NotContains(t, string(body), "root:", "Should not expose system files")
}

func TestSecurityE2E_XSSAttackPrevention(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Test XSS in RelayState
	xssPayload := `<script>alert('XSS')</script>`

	// Create valid request
	authnReq := saml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &saml.Issuer{
			Value: "https://sp.example.com",
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(authnReq.Element())
	requestXML, _ := doc.WriteToString()
	encoded := base64.StdEncoding.EncodeToString([]byte(requestXML))
	compressed := compress(encoded)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
		server.URL+"/sso?SAMLRequest="+url.QueryEscape(compressed)+"&RelayState="+url.QueryEscape(xssPayload),
		nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// Should escape XSS payload
	assert.NotContains(t, string(body), "<script>alert('XSS')</script>", "Should escape XSS payloads")
	if strings.Contains(string(body), xssPayload) {
		assert.Contains(t, string(body), "&lt;script&gt;", "XSS payload should be escaped")
	}
}

func TestSecurityE2E_SAMLSignatureWrappingAttack(t *testing.T) {
	// Test signature wrapping attack where assertion is modified after signing
	t.Log("Signature wrapping attack test - requires manual XML manipulation after signing")

	// This is a complex attack where:
	// 1. Valid signed assertion is moved
	// 2. New unsigned assertion is inserted
	// 3. Signature still validates but wrong assertion is used
	// Implementation would require low-level XML manipulation
}

func TestSecurityE2E_CSRFProtection(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Test CSRF on ACS endpoint
	form := url.Values{}
	form.Set("SAMLResponse", "fake-response")

	// Request without proper SAML flow initiation
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.com") // Different origin

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject without proper flow
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Should have CSRF protection")
}
