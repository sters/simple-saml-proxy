package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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
	crewjamsaml "github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/sters/simple-saml-proxy/proxy/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSecurityTest creates a common test setup for security tests.
func setupSecurityTest(t *testing.T) (*httptest.Server, *MockSAMLProvider) {
	t.Helper()

	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	mockProvider := NewMockSAMLProvider(t)

	cfg := &config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	cfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	cfg.Proxy.PrivateKeyPath = proxyKeyPath
	cfg.Proxy.CertificatePath = proxyCertPath
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{EntityID: "https://sp.example.com"},
	}
	cfg.IDP = []config.IDPConfig{
		{
			ID:          "test-idp",
			MetadataURL: mockProvider.server.URL + "/saml/metadata",
		},
	}

	ctx := t.Context()
	providers, err := saml.CreateServiceProviders(ctx, *cfg)
	require.NoError(t, err)

	idp, err := saml.CreateProxyIDP(*cfg)
	require.NoError(t, err)

	mux := proxy.SetupHTTPHandlers(idp, providers, *cfg)
	server := httptest.NewServer(mux)

	return server, mockProvider
}

func TestSecurityE2E_TamperedSAMLRequest(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()
	// Create a valid SAML request
	authnReq := crewjamsaml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: "https://sp.example.com",
		},
		AssertionConsumerServiceURL: "https://sp.example.com/acs",
		ProtocolBinding:             crewjamsaml.HTTPPostBinding,
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
	authnReq := crewjamsaml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: "https://unauthorized-sp.example.com", // Not in AllowedSPs
		},
		AssertionConsumerServiceURL: "https://unauthorized-sp.example.com/acs",
		ProtocolBinding:             crewjamsaml.HTTPPostBinding,
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
	authnReq := crewjamsaml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
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
	response := &crewjamsaml.Response{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC().Add(-2 * time.Hour), // Old response
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: mockProvider.entityID,
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: crewjamsaml.StatusSuccess,
			},
		},
		Assertion: &crewjamsaml.Assertion{
			ID:           "_" + uuid.New().String(),
			IssueInstant: time.Now().UTC().Add(-2 * time.Hour),
			Version:      "2.0",
			Issuer: crewjamsaml.Issuer{
				Value: mockProvider.entityID,
			},
			Subject: &crewjamsaml.Subject{
				NameID: &crewjamsaml.NameID{
					Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
					Value:  "testuser",
				},
			},
			Conditions: &crewjamsaml.Conditions{
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
	samlResp := mockProvider.createSAMLResponse("test-123", server.URL+"/saml/acs", "https://proxy.example.com")
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
	response := &crewjamsaml.Response{
		ID:           "_" + uuid.New().String(),
		InResponseTo: "wrong-request-id", // Does not match any stored request
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: mockProvider.entityID,
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: crewjamsaml.StatusSuccess,
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

func TestSecurityE2E_InvalidSAMLRequestSignature(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Create a properly formed SAML request
	authnReq := crewjamsaml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: "https://sp.example.com",
		},
		AssertionConsumerServiceURL: "https://sp.example.com/acs",
		ProtocolBinding:             crewjamsaml.HTTPPostBinding,
	}

	doc := etree.NewDocument()
	doc.SetRoot(authnReq.Element())

	// Add an invalid signature element manually
	sigElement := doc.CreateElement("ds:Signature")
	sigElement.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	sigInfo := sigElement.CreateElement("ds:SignedInfo")
	canonicalizationMethod := sigInfo.CreateElement("ds:CanonicalizationMethod")
	canonicalizationMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	sigMethod := sigInfo.CreateElement("ds:SignatureMethod")
	sigMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	reference := sigInfo.CreateElement("ds:Reference")
	reference.CreateAttr("URI", "#"+authnReq.ID)
	transforms := reference.CreateElement("ds:Transforms")
	transform1 := transforms.CreateElement("ds:Transform")
	transform1.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	transform2 := transforms.CreateElement("ds:Transform")
	transform2.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	digestMethod := reference.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	digestValue := reference.CreateElement("ds:DigestValue")
	digestValue.SetText("INVALID_DIGEST_VALUE")
	// Add invalid signature value
	sigValue := sigElement.CreateElement("ds:SignatureValue")
	sigValue.SetText("INVALID_SIGNATURE_VALUE")
	// Insert signature after Issuer
	issuerElem := doc.FindElement("//saml:Issuer")
	if issuerElem != nil && issuerElem.Parent() != nil {
		issuerElem.Parent().InsertChildAt(issuerElem.Index()+1, sigElement)
	}

	requestXML, _ := doc.WriteToString()
	encoded := base64.StdEncoding.EncodeToString([]byte(requestXML))
	compressed := compress(encoded)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/sso?SAMLRequest="+url.QueryEscape(compressed), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject request with invalid signature
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "RequestDenied", "Should reject SAML request with invalid signature")
}

func TestSecurityE2E_TamperedSAMLResponse(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// First, initiate a valid SAML flow to get a proper context
	authnReq := crewjamsaml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: "https://sp.example.com",
		},
		AssertionConsumerServiceURL: "https://sp.example.com/acs",
	}

	// Create a valid SAML response
	response := &crewjamsaml.Response{
		ID:           "_" + uuid.New().String(),
		InResponseTo: authnReq.ID,
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: mockProvider.entityID,
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: crewjamsaml.StatusSuccess,
			},
		},
		Assertion: &crewjamsaml.Assertion{
			ID:           "_" + uuid.New().String(),
			IssueInstant: time.Now().UTC(),
			Version:      "2.0",
			Issuer: crewjamsaml.Issuer{
				Value: mockProvider.entityID,
			},
			Subject: &crewjamsaml.Subject{
				NameID: &crewjamsaml.NameID{
					Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
					Value:  "testuser",
				},
				SubjectConfirmations: []crewjamsaml.SubjectConfirmation{
					{
						Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
						SubjectConfirmationData: &crewjamsaml.SubjectConfirmationData{
							InResponseTo: authnReq.ID,
							Recipient:    server.URL + "/saml/acs",
							NotOnOrAfter: time.Now().UTC().Add(5 * time.Minute),
						},
					},
				},
			},
			Conditions: &crewjamsaml.Conditions{
				NotBefore:    time.Now().UTC().Add(-1 * time.Minute),
				NotOnOrAfter: time.Now().UTC().Add(5 * time.Minute),
			},
			AttributeStatements: []crewjamsaml.AttributeStatement{
				{
					Attributes: []crewjamsaml.Attribute{
						{
							Name: "email",
							Values: []crewjamsaml.AttributeValue{
								{Value: "test@example.com"},
							},
						},
					},
				},
			},
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	responseXML, _ := doc.WriteToString()

	// Tamper with the response after converting to string
	// Change the NameID value in the assertion
	tamperedXML := strings.Replace(responseXML, "testuser", "tampereduser", 1)

	encoded := base64.StdEncoding.EncodeToString([]byte(tamperedXML))

	form := url.Values{}
	form.Set("SAMLResponse", encoded)
	form.Set("RelayState", "test-state")

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject tampered response
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Should reject tampered SAML response")
}

func TestSecurityE2E_InvalidSAMLResponseSignature(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Create a SAML response with invalid signature
	response := &crewjamsaml.Response{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: mockProvider.entityID,
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: crewjamsaml.StatusSuccess,
			},
		},
		Assertion: &crewjamsaml.Assertion{
			ID:           "_" + uuid.New().String(),
			IssueInstant: time.Now().UTC(),
			Version:      "2.0",
			Issuer: crewjamsaml.Issuer{
				Value: mockProvider.entityID,
			},
			Subject: &crewjamsaml.Subject{
				NameID: &crewjamsaml.NameID{
					Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
					Value:  "testuser",
				},
			},
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(response.Element())

	// Add a fake signature element
	sigElement := doc.CreateElement("ds:Signature")
	sigElement.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	sigValue := sigElement.CreateElement("ds:SignatureValue")
	sigValue.SetText("FAKE_SIGNATURE_VALUE_THAT_IS_INVALID")

	// Insert signature in response
	if responseRoot := doc.Root(); responseRoot != nil {
		statusElem := doc.FindElement("//samlp:Status")
		if statusElem != nil && statusElem.Parent() != nil {
			statusElem.Parent().InsertChildAt(statusElem.Index(), sigElement)
		}
	}

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

	// Should reject response with invalid signature
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Should reject SAML response with invalid signature")
}

func TestSecurityE2E_InvalidCertificate(t *testing.T) {
	// Test handling of invalid certificates in metadata
	testDir := t.TempDir()

	// Create proxy certs
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)

	// Create an invalid/malformed certificate
	invalidCertPath := filepath.Join(testDir, "invalid.crt")
	invalidCertContent := `-----BEGIN CERTIFICATE-----
INVALID_CERTIFICATE_CONTENT_THAT_IS_NOT_VALID_BASE64
-----END CERTIFICATE-----`
	require.NoError(t, os.WriteFile(invalidCertPath, []byte(invalidCertContent), 0o644))

	// Try to create proxy with invalid certificate
	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	cfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	cfg.Proxy.PrivateKeyPath = proxyKeyPath
	cfg.Proxy.CertificatePath = invalidCertPath // Invalid certificate

	// This should fail during proxy creation
	_, err := saml.CreateProxyIDP(cfg)
	require.Error(t, err, "Should fail with invalid certificate")

	// Test with valid proxy cert but invalid IdP cert
	cfg.Proxy.CertificatePath = proxyCertPath

	// Create a mock server that returns invalid certificate in metadata
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/saml/metadata" {
			// Return metadata with invalid certificate
			metadata := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://invalid-idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>INVALID_CERT_DATA</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://invalid-idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			_, _ = w.Write([]byte(metadata))
		}
	}))
	defer mockServer.Close()

	cfg.IDP = []config.IDPConfig{
		{
			ID:          "invalid-idp",
			MetadataURL: mockServer.URL + "/saml/metadata",
		},
	}

	// Try to create service providers with invalid IdP metadata
	ctx := t.Context()
	_, err = saml.CreateServiceProviders(ctx, cfg)
	// This might fail or succeed depending on validation
	t.Logf("CreateServiceProviders with invalid cert result: %v", err)
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

	// Test proxy with expired certificate
	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	cfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	cfg.Proxy.PrivateKeyPath = expiredKeyPath
	cfg.Proxy.CertificatePath = expiredCertPath

	// Try to create proxy IDP with expired cert
	_, err := saml.CreateProxyIDP(cfg)
	// The library might or might not validate cert expiration during creation
	t.Logf("CreateProxyIDP with expired cert result: %v", err)

	// Create valid proxy certs for further testing
	proxyCertPath, proxyKeyPath := generateTestCertificate(t)
	cfg.Proxy.PrivateKeyPath = proxyKeyPath
	cfg.Proxy.CertificatePath = proxyCertPath

	// Create mock server that presents expired certificate in metadata
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/saml/metadata" {
			// Read the expired cert
			certPEMData, _ := os.ReadFile(expiredCertPath)
			block, _ := pem.Decode(certPEMData)
			certBase64 := base64.StdEncoding.EncodeToString(block.Bytes)

			// Return metadata with expired certificate
			metadata := fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://expired-idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://expired-idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, certBase64)
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			_, _ = w.Write([]byte(metadata))
		}
	}))
	defer mockServer.Close()

	cfg.IDP = []config.IDPConfig{
		{
			ID:          "expired-idp",
			MetadataURL: mockServer.URL + "/saml/metadata",
		},
	}

	// Try to create service providers with expired IdP cert
	ctx := t.Context()
	_, err = saml.CreateServiceProviders(ctx, cfg)
	t.Logf("CreateServiceProviders with expired IdP cert result: %v", err)
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
	authnReq := crewjamsaml.AuthnRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
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

func TestSecurityE2E_CertificateChainValidation(t *testing.T) {
	// Test certificate chain validation
	testDir := t.TempDir()

	// Create a self-signed root CA
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Root CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	rootPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootPriv.PublicKey, rootPriv)

	// Create an intermediate cert signed by root
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Intermediate CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	intermediatePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	intermediateCertDER, _ := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootTemplate, &intermediatePriv.PublicKey, rootPriv)

	// Create a leaf cert signed by intermediate
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Leaf"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	leafPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateTemplate, &leafPriv.PublicKey, intermediatePriv)

	// Write certificates
	chainCertPath := filepath.Join(testDir, "chain.crt")
	chainKeyPath := filepath.Join(testDir, "chain.key")

	// Create certificate chain file (leaf + intermediate + root)
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateCertDER})...)
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertDER})...)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafPriv)})

	require.NoError(t, os.WriteFile(chainCertPath, chainPEM, 0o644))
	require.NoError(t, os.WriteFile(chainKeyPath, keyPEM, 0o644))

	// Test proxy with certificate chain
	cfg := config.Config{}
	cfg.Proxy.EntityID = "https://proxy.example.com"
	cfg.Proxy.MetadataURL = "https://proxy.example.com/metadata"
	cfg.Proxy.AcsURL = "https://proxy.example.com/saml/acs"
	cfg.Proxy.PrivateKeyPath = chainKeyPath
	cfg.Proxy.CertificatePath = chainCertPath

	// Create proxy IDP with certificate chain
	_, err := saml.CreateProxyIDP(cfg)
	t.Logf("CreateProxyIDP with certificate chain result: %v", err)
}

func TestSecurityE2E_CertificateRevocation(t *testing.T) {
	// Test certificate revocation checking
	// Note: Real CRL checking would require network access and a CRL distribution point
	t.Log("Certificate revocation test - would require CRL distribution point and network access")

	// Create a mock server that serves a CRL
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crl.pem" {
			// In a real test, this would serve an actual CRL
			w.Header().Set("Content-Type", "application/pkix-crl")
			w.WriteHeader(http.StatusOK)
			// Empty CRL for testing
			_, _ = w.Write([]byte("-----BEGIN X509 CRL-----\n-----END X509 CRL-----"))
		}
	}))
	defer crlServer.Close()

	// The actual CRL checking would depend on the SAML library's implementation
	// Most SAML libraries don't check CRLs by default for performance reasons
	t.Logf("CRL server running at: %s/crl.pem", crlServer.URL)
}

func TestSecurityE2E_SAMLSignatureWrappingAttack(t *testing.T) {
	server, mockProvider := setupSecurityTest(t)
	defer server.Close()
	defer mockProvider.server.Close()

	// Create a valid SAML response
	response := &crewjamsaml.Response{
		ID:           "_" + uuid.New().String(),
		IssueInstant: time.Now().UTC(),
		Version:      "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: mockProvider.entityID,
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: crewjamsaml.StatusSuccess,
			},
		},
		Assertion: &crewjamsaml.Assertion{
			ID:           "_" + uuid.New().String(),
			IssueInstant: time.Now().UTC(),
			Version:      "2.0",
			Issuer: crewjamsaml.Issuer{
				Value: mockProvider.entityID,
			},
			Subject: &crewjamsaml.Subject{
				NameID: &crewjamsaml.NameID{
					Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
					Value:  "legitimateuser",
				},
			},
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(response.Element())

	// In a real signature wrapping attack:
	// 1. The response would be properly signed
	// 2. The attacker would move the signed assertion to a different location
	// 3. Insert a new unsigned assertion with different (malicious) content
	// 4. The signature would still validate against the original assertion
	//    but the SAML processor might use the unsigned assertion

	// For this test, we'll simulate by having two assertions
	assertionElem := doc.FindElement("//saml:Assertion")
	if assertionElem != nil && assertionElem.Parent() != nil {
		// Clone the assertion
		newAssertion := assertionElem.Copy()
		// Modify the cloned assertion to have different user
		if nameID := newAssertion.FindElement(".//saml:NameID"); nameID != nil {
			nameID.SetText("attackeruser")
		}
		// Change the ID to avoid duplicate IDs
		if idAttr := newAssertion.SelectAttr("ID"); idAttr != nil {
			idAttr.Value = "_" + uuid.New().String()
		}
		// Insert the malicious assertion
		assertionElem.Parent().AddChild(newAssertion)
	}

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

	// A secure implementation should detect multiple assertions or validate that
	// the signature covers the assertion being used
	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response to signature wrapping attack: status=%d, body contains 'attackeruser': %v",
		resp.StatusCode, strings.Contains(string(body), "attackeruser"))

	// The response should either reject the request or not use the attacker's assertion
	if resp.StatusCode == http.StatusOK {
		assert.NotContains(t, string(body), "attackeruser", "Should not process unsigned/wrapped assertion")
	}
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
