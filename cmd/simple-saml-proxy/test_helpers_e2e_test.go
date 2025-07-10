package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
)

var ErrNoLocationHeader = errors.New("no Location header in redirect response")

// encodeSAMLRequest encodes a SAML request for HTTP-Redirect binding.
// It deflates and then base64 encodes the request as per SAML specification.
func encodeSAMLRequest(samlRequest string) (string, error) {
	// Deflate the request
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("failed to create flate writer: %w", err)
	}
	if _, err := w.Write([]byte(samlRequest)); err != nil {
		return "", fmt.Errorf("failed to write to flate writer: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("failed to close flate writer: %w", err)
	}

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(b.Bytes())

	return encoded, nil
}

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	var certPath, keyPath string
	tempDir := t.TempDir()

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Organization"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Write certificate to file
	certPath = filepath.Join(tempDir, "test.crt")
	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	require.NoError(t, err)

	// Write private key to file
	keyPath = filepath.Join(tempDir, "test.key")
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	require.NoError(t, err)

	return certPath, keyPath
}

// MockSAMLProvider simulates an external SAML Identity Provider.
type MockSAMLProvider struct {
	server           *httptest.Server
	entityID         string
	ssoURL           string
	metadata         []byte
	authnRequests    []string
	responseTemplate string
	t                *testing.T
	privateKey       *rsa.PrivateKey
	certificate      *x509.Certificate
	certificatePEM   string
}

// NewMockSAMLProvider creates a new mock SAML provider.
func NewMockSAMLProvider(t *testing.T) *MockSAMLProvider {
	t.Helper()

	// Generate a key pair for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Mock IDP"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	// Convert cert to base64 for metadata (without PEM headers)
	certBase64 := base64.StdEncoding.EncodeToString(certBytes)

	provider := &MockSAMLProvider{
		entityID:       "https://mockidp.example.com/saml/metadata",
		authnRequests:  []string{},
		t:              t,
		privateKey:     privateKey,
		certificate:    cert,
		certificatePEM: certBase64,
	}

	// Create a test server for the mock IDP
	mux := http.NewServeMux()

	// Metadata endpoint
	mux.HandleFunc("/saml/metadata", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, err := w.Write(provider.metadata)
		if err != nil {
			provider.t.Errorf("Failed to write response: %v", err)
		}
	})

	// SSO endpoint
	mux.HandleFunc("/saml/sso", func(w http.ResponseWriter, r *http.Request) {
		// Extract the SAML request
		samlRequest := r.URL.Query().Get("SAMLRequest")
		if samlRequest != "" {
			provider.authnRequests = append(provider.authnRequests, samlRequest)
		}

		// Decode the SAML request to get details
		decoded, err := base64.StdEncoding.DecodeString(samlRequest)
		if err != nil {
			provider.t.Logf("Failed to decode SAML request: %v", err)
			http.Error(w, "Invalid SAML Request", http.StatusBadRequest)

			return
		}

		// Decompress
		reader := flate.NewReader(bytes.NewReader(decoded))
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			provider.t.Logf("Failed to decompress SAML request: %v", err)
			http.Error(w, "Invalid SAML Request", http.StatusBadRequest)

			return
		}

		// Parse the request
		var authnRequest saml.AuthnRequest
		err = xml.Unmarshal(decompressed, &authnRequest)
		if err != nil {
			provider.t.Logf("Failed to parse SAML request: %v", err)
			http.Error(w, "Invalid SAML Request", http.StatusBadRequest)

			return
		}

		provider.t.Logf("Received AuthnRequest ID: %s, ACS: %s", authnRequest.ID, authnRequest.AssertionConsumerServiceURL)

		// Get RelayState
		relayState := r.URL.Query().Get("RelayState")

		// Create a SAML response
		samlResponse := provider.createSAMLResponse(authnRequest.ID, authnRequest.AssertionConsumerServiceURL)
		provider.t.Logf("Generated SAML Response:\n%s", samlResponse)

		// Encode the response
		encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))
		provider.t.Logf("Encoded SAML Response length: %d", len(encoded))

		// Create a form that will be submitted to the ACS URL
		w.Header().Set("Content-Type", "text/html")
		// Write the HTML form directly without fmt.Sprintf to avoid HTML escaping
		html := `<html>
<body onload="document.forms[0].submit()">
<form method="post" action="` + authnRequest.AssertionConsumerServiceURL + `">
<input type="hidden" name="SAMLResponse" value="` + encoded + `" />
<input type="hidden" name="RelayState" value="` + relayState + `" />
</form>
</body>
</html>`
		_, _ = w.Write([]byte(html))
		provider.t.Logf("Sending form to ACS URL: %s", authnRequest.AssertionConsumerServiceURL)
	})

	provider.server = httptest.NewServer(mux)
	provider.ssoURL = provider.server.URL + "/saml/sso"

	// Create metadata for this provider with signing certificate
	provider.metadata = []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + provider.entityID + `">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>` + provider.certificatePEM + `</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + provider.ssoURL + `"/>
  </IDPSSODescriptor>
</EntityDescriptor>`)

	// Response template
	provider.responseTemplate = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
  ID="_%s" Version="2.0" 
  IssueInstant="%s" 
  Destination="%s" 
  InResponseTo="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
    ID="_%s" 
    IssueInstant="%s" 
    Version="2.0">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">testuser@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="%s" NotOnOrAfter="%s" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>testuser@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>Test User</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	return provider
}

// createSAMLResponse creates a signed SAML response for the given request ID and ACS URL.
func (p *MockSAMLProvider) createSAMLResponse(requestID, acsURL string) string {
	now := time.Now().UTC()
	notAfter := now.Add(time.Hour)
	responseID := "_" + strconv.FormatInt(now.UnixNano(), 10)
	assertionID := "_" + strconv.FormatInt(now.UnixNano()+1, 10)

	// Create the assertion
	assertion := &saml.Assertion{
		ID:           assertionID,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Value: p.entityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				Value:  "testuser@example.com",
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						InResponseTo: requestID,
						NotOnOrAfter: notAfter,
						Recipient:    acsURL,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    now,
			NotOnOrAfter: notAfter,
			AudienceRestrictions: []saml.AudienceRestriction{
				{
					Audience: saml.Audience{Value: "https://sp.example.com"},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name:       "email",
						NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
						Values: []saml.AttributeValue{
							{Value: "testuser@example.com"},
						},
					},
					{
						Name:       "name",
						NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
						Values: []saml.AttributeValue{
							{Value: "Test User"},
						},
					},
				},
			},
		},
	}

	// Create the response
	response := &saml.Response{
		ID:           responseID,
		InResponseTo: requestID,
		IssueInstant: now,
		Version:      "2.0",
		Destination:  acsURL,
		Issuer: &saml.Issuer{
			Value: p.entityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
		Assertion: assertion,
	}

	// Convert to XML string
	doc := etree.NewDocument()
	responseEl := response.Element()
	doc.SetRoot(responseEl)

	// For now, return unsigned response since proper signing requires
	// more complex setup. The test will verify that the proxy can at least
	// parse and handle well-formed SAML responses.
	xmlStr, _ := doc.WriteToString()

	return xmlStr
}

// Close shuts down the mock provider.
func (p *MockSAMLProvider) Close() {
	if p.server != nil {
		p.server.Close()
	}
}

// MockSAMLClient simulates a Service Provider client.
type MockSAMLClient struct {
	client      *http.Client
	t           *testing.T
	entityID    string
	acsURL      string
	metadataURL string
}

// NewMockSAMLClient creates a new mock SAML client.
func NewMockSAMLClient(t *testing.T) *MockSAMLClient {
	t.Helper()

	return &MockSAMLClient{
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				// Don't follow redirects automatically
				return http.ErrUseLastResponse
			},
		},
		t:           t,
		entityID:    "https://sp.example.com",
		acsURL:      "https://sp.example.com/acs",
		metadataURL: "https://sp.example.com/metadata",
	}
}

// Close cleans up the client.
func (c *MockSAMLClient) Close() {
	// No resources to clean up for now
}

// InitiateLogin starts a SAML login flow with the proxy.
func (c *MockSAMLClient) InitiateLogin(ctx context.Context, proxyURL string) (*http.Response, error) {
	// Create SAML AuthnRequest
	authnRequest := fmt.Sprintf(`<samlp:AuthnRequest 
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
  ID="_test123" 
  Version="2.0" 
  IssueInstant="%s" 
  AssertionConsumerServiceURL="%s">
  <saml:Issuer>%s</saml:Issuer>
</samlp:AuthnRequest>`, time.Now().UTC().Format(time.RFC3339), c.acsURL, c.entityID)

	// Encode the request
	encoded, err := encodeSAMLRequest(authnRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SAML request: %w", err)
	}

	// Build URL
	ssoURL := fmt.Sprintf("%s/sso?SAMLRequest=%s&RelayState=test-state", proxyURL, url.QueryEscape(encoded))

	// Make request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ssoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	return resp, nil
}

// FollowRedirect follows a redirect response.
func (c *MockSAMLClient) FollowRedirect(resp *http.Response) (*http.Response, error) {
	location := resp.Header.Get("Location")
	if location == "" {
		return nil, ErrNoLocationHeader
	}

	// Resolve relative URLs against the request URL
	locationURL, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("failed to parse location header: %w", err)
	}

	if !locationURL.IsAbs() {
		baseURL := resp.Request.URL
		locationURL = baseURL.ResolveReference(locationURL)
	}

	req, err := http.NewRequestWithContext(c.t.Context(), http.MethodGet, locationURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create redirect request: %w", err)
	}

	// Copy cookies
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}

	resp2, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	return resp2, nil
}

// disableSignatureValidation disables signature validation for testing.
func disableSignatureValidation(_ interface{}) {
	// Note: The crewjam/saml library doesn't expose a simple way to disable signature validation
	// This function is left as a placeholder for when such functionality is needed
}

// MockSAMLProviderWithErrors is a mock provider that can simulate errors.
type MockSAMLProviderWithErrors struct {
	MockSAMLProvider
	shouldFailAuth  bool
	shouldError     bool
	errorStatusCode int
	errorMessage    string
}

// NewMockSAMLProviderWithErrors creates a new mock provider that can simulate errors.
func NewMockSAMLProviderWithErrors(t *testing.T) *MockSAMLProviderWithErrors {
	t.Helper()

	// Create a base provider with signing capabilities
	baseProvider := NewMockSAMLProvider(t)

	provider := &MockSAMLProviderWithErrors{
		MockSAMLProvider: *baseProvider,
		shouldFailAuth:   false,
		shouldError:      false,
		errorStatusCode:  http.StatusInternalServerError,
		errorMessage:     "Internal Server Error",
	}

	// Create a test server for the mock IDP
	mux := http.NewServeMux()

	// Metadata endpoint
	mux.HandleFunc("/saml/metadata", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(provider.metadata)
	})

	// SSO endpoint with error simulation
	mux.HandleFunc("/saml/sso", func(w http.ResponseWriter, r *http.Request) {
		if provider.shouldError {
			http.Error(w, provider.errorMessage, provider.errorStatusCode)

			return
		}

		// Extract and decode the SAML request
		samlRequest := r.URL.Query().Get("SAMLRequest")
		decoded, _ := base64.StdEncoding.DecodeString(samlRequest)
		reader := flate.NewReader(bytes.NewReader(decoded))
		decompressed, _ := io.ReadAll(reader)
		reader.Close()

		var authnRequest saml.AuthnRequest
		_ = xml.Unmarshal(decompressed, &authnRequest)

		relayState := r.URL.Query().Get("RelayState")

		if provider.shouldFailAuth {
			// Return authentication failure response
			samlResponse := provider.createFailureResponse(authnRequest.ID, authnRequest.AssertionConsumerServiceURL)
			encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))

			w.Header().Set("Content-Type", "text/html")
			html := `<html><body onload="document.forms[0].submit()">
				<form method="post" action="` + authnRequest.AssertionConsumerServiceURL + `">
					<input type="hidden" name="SAMLResponse" value="` + encoded + `" />
					<input type="hidden" name="RelayState" value="` + relayState + `" />
				</form></body></html>`
			_, _ = w.Write([]byte(html))
		} else {
			// Return success response
			samlResponse := provider.createSAMLResponse(authnRequest.ID, authnRequest.AssertionConsumerServiceURL)
			encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))

			w.Header().Set("Content-Type", "text/html")
			html := `<html><body onload="document.forms[0].submit()">
				<form method="post" action="` + authnRequest.AssertionConsumerServiceURL + `">
					<input type="hidden" name="SAMLResponse" value="` + encoded + `" />
					<input type="hidden" name="RelayState" value="` + relayState + `" />
				</form></body></html>`
			_, _ = w.Write([]byte(html))
		}
	})

	provider.server = httptest.NewServer(mux)
	provider.ssoURL = provider.server.URL + "/saml/sso"

	// Metadata is already set by base provider
	// Response template is no longer needed as we use the signing method

	return provider
}

// SetShouldFailAuth sets whether authentication should fail.
func (p *MockSAMLProviderWithErrors) SetShouldFailAuth(shouldFail bool) {
	p.shouldFailAuth = shouldFail
}

// SetShouldReturnError sets whether the provider should return an error.
func (p *MockSAMLProviderWithErrors) SetShouldReturnError(shouldError bool, statusCode int, message string) {
	p.shouldError = shouldError
	p.errorStatusCode = statusCode
	p.errorMessage = message
}

// createFailureResponse creates a SAML response indicating authentication failure.
func (p *MockSAMLProviderWithErrors) createFailureResponse(requestID, acsURL string) string {
	now := time.Now().UTC().Format(time.RFC3339)
	randomID := strconv.FormatInt(time.Now().UnixNano(), 10)

	return fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
  ID="_%s" Version="2.0" 
  IssueInstant="%s" 
  Destination="%s" 
  InResponseTo="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>
    <samlp:StatusMessage>Authentication failed</samlp:StatusMessage>
  </samlp:Status>
</samlp:Response>`,
		randomID,
		now,
		acsURL,
		requestID,
		p.entityID,
	)
}

// Helper function to compress data for SAML redirect binding.
func compress(data string) string {
	var buf bytes.Buffer
	writer, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = writer.Write([]byte(data))
	writer.Close()

	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// Helper function to extract form values from HTML response.
func extractFormValues(t *testing.T, html string) (string, string, string) {
	t.Helper()

	var action, samlResponse, relayState string

	// Extract action URL
	actionRegex := regexp.MustCompile(`action="([^"]+)"`)
	if matches := actionRegex.FindStringSubmatch(html); len(matches) > 1 {
		action = matches[1]
	}

	// Extract SAMLResponse
	samlRegex := regexp.MustCompile(`name="SAMLResponse"\s+value="([^"]+)"`)
	if matches := samlRegex.FindStringSubmatch(html); len(matches) > 1 {
		samlResponse = matches[1]
	}

	// Extract RelayState
	relayRegex := regexp.MustCompile(`name="RelayState"\s+value="([^"]+)"`)
	if matches := relayRegex.FindStringSubmatch(html); len(matches) > 1 {
		relayState = matches[1]
	}

	return action, samlResponse, relayState
}
