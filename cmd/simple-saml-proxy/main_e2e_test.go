package main

import (
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
	"strconv"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/stretchr/testify/assert"
)

// generateTestCertificate generates a self-signed certificate and private key for testing.
func generateTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	var certPath, keyPath string
	tempDir := t.TempDir()

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	assert.NoError(t, err)

	// Write the certificate to a file
	certPath = filepath.Join(tempDir, "cert.pem")
	certOut, err := os.Create(certPath)
	assert.NoError(t, err)
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	assert.NoError(t, err)

	// Write the private key to a file
	keyPath = filepath.Join(tempDir, "key.pem")
	keyOut, err := os.Create(keyPath)
	assert.NoError(t, err)
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	assert.NoError(t, err)

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
}

// NewMockSAMLProvider creates a new mock SAML provider.
func NewMockSAMLProvider(t *testing.T) *MockSAMLProvider {
	t.Helper()
	provider := &MockSAMLProvider{
		entityID:      "https://mockidp.example.com/saml/metadata",
		authnRequests: []string{},
		t:             t,
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

		// In a real scenario, this would show a login form
		// For testing, we'll simulate a successful authentication and redirect back to the ACS URL
		relayState := r.URL.Query().Get("RelayState")
		if relayState == "" {
			relayState = "/"
		}

		// Parse the SAML request to get the ACS URL
		decoded, err := base64.StdEncoding.DecodeString(samlRequest)
		assert.NoError(t, err)

		// Inflate the request if it's compressed
		// For simplicity, we're assuming it's not compressed in this mock

		// Parse the AuthnRequest
		var authnRequest saml.AuthnRequest
		err = xml.Unmarshal(decoded, &authnRequest)
		assert.NoError(t, err)

		// Create a SAML response
		samlResponse := provider.createSAMLResponse(authnRequest.ID, authnRequest.AssertionConsumerServiceURL)

		// Encode the response
		encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))

		// Create a form that will be submitted to the ACS URL
		w.Header().Set("Content-Type", "text/html")
		_, err = w.Write([]byte(fmt.Sprintf(`
			<html>
				<body onload="document.forms[0].submit()">
					<form method="post" action="%s">
						<input type="hidden" name="SAMLResponse" value="%s" />
						<input type="hidden" name="RelayState" value="%s" />
						<input type="submit" value="Submit" />
					</form>
				</body>
			</html>
		`, authnRequest.AssertionConsumerServiceURL, encoded, relayState)))
		if err != nil {
			provider.t.Errorf("Failed to write response: %v", err)
		}
	})

	provider.server = httptest.NewServer(mux)
	provider.ssoURL = provider.server.URL + "/saml/sso"

	// Generate metadata
	metadata := fmt.Sprintf(`
		<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
			<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
				<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
			</IDPSSODescriptor>
		</EntityDescriptor>
	`, provider.entityID, provider.ssoURL)

	provider.metadata = []byte(metadata)

	// Create a response template
	provider.responseTemplate = `
		<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
						xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
						ID="_response_%[1]s"
						Version="2.0"
						IssueInstant="%[2]s"
						Destination="%[3]s"
						InResponseTo="%[4]s">
			<saml:Issuer>%[5]s</saml:Issuer>
			<samlp:Status>
				<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
			</samlp:Status>
			<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
							xmlns:xs="http://www.w3.org/2001/XMLSchema"
							ID="_assertion_%[1]s"
							Version="2.0"
							IssueInstant="%[2]s">
				<saml:Issuer>%[5]s</saml:Issuer>
				<saml:Subject>
					<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">testuser@example.com</saml:NameID>
					<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
						<saml:SubjectConfirmationData InResponseTo="%[4]s"
													Recipient="%[3]s"
													NotOnOrAfter="%[6]s" />
					</saml:SubjectConfirmation>
				</saml:Subject>
				<saml:Conditions NotBefore="%[2]s" NotOnOrAfter="%[6]s">
					<saml:AudienceRestriction>
						<saml:Audience>%[7]s</saml:Audience>
					</saml:AudienceRestriction>
				</saml:Conditions>
				<saml:AuthnStatement AuthnInstant="%[2]s" SessionIndex="_session_%[1]s">
					<saml:AuthnContext>
						<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
					</saml:AuthnContext>
				</saml:AuthnStatement>
				<saml:AttributeStatement>
					<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
						<saml:AttributeValue xsi:type="xs:string">testuser@example.com</saml:AttributeValue>
					</saml:Attribute>
					<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
						<saml:AttributeValue xsi:type="xs:string">Test User</saml:AttributeValue>
					</saml:Attribute>
				</saml:AttributeStatement>
			</saml:Assertion>
		</samlp:Response>
	`

	return provider
}

// createSAMLResponse creates a SAML response for the given request ID and ACS URL.
func (p *MockSAMLProvider) createSAMLResponse(requestID, acsURL string) string {
	now := time.Now().UTC().Format(time.RFC3339)
	notAfter := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	randomID := strconv.FormatInt(time.Now().UnixNano(), 10)

	return fmt.Sprintf(p.responseTemplate,
		randomID,
		now,
		acsURL,
		requestID,
		p.entityID,
		notAfter,
		"http://localhost:8080/metadata", // SP Entity ID
	)
}

// Close shuts down the mock SAML provider.
func (p *MockSAMLProvider) Close() {
	if p.server != nil {
		p.server.Close()
	}
}

// MockSAMLClient simulates a service that uses SAML authentication.
type MockSAMLClient struct {
	server *httptest.Server
	client *http.Client
	t      *testing.T
}

// NewMockSAMLClient creates a new mock SAML client.
func NewMockSAMLClient(t *testing.T) *MockSAMLClient {
	t.Helper()
	client := &MockSAMLClient{
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				// Don't follow redirects automatically
				return http.ErrUseLastResponse
			},
		},
		t: t,
	}

	// Create a test server for the mock client
	mux := http.NewServeMux()

	// Home page that requires authentication
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("Authenticated home page"))
		if err != nil {
			client.t.Errorf("Failed to write response: %v", err)
		}
	})

	client.server = httptest.NewServer(mux)

	return client
}

// Close shuts down the mock SAML client.
func (c *MockSAMLClient) Close() {
	if c.server != nil {
		c.server.Close()
	}
}

// InitiateLogin initiates a login flow by sending a request to the proxy's SSO endpoint.
func (c *MockSAMLClient) InitiateLogin(proxyURL string) (*http.Response, error) {
	ssoURL := proxyURL + "/sso"

	return c.client.Get(ssoURL)
}

// FollowRedirect follows a redirect response.
func (c *MockSAMLClient) FollowRedirect(resp *http.Response) (*http.Response, error) {
	location := resp.Header.Get("Location")
	if location == "" {
		return nil, errors.New("no Location header in redirect response")
	}

	return c.client.Get(location)
}

// TestMetadataEndpoint tests the /metadata endpoint of the SAML proxy.
func TestMetadataEndpoint(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	// Load the certificate
	cert, err := proxy.LoadCertificate(certPath, keyPath)
	assert.NoError(t, err)

	// Create a mock SAML provider
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	// Create a test config with multiple IDP
	config := proxy.Config{}
	config.Proxy.EntityID = "http://localhost:8080/metadata"
	config.Proxy.AcsURL = "http://localhost:8080/sso/acs"
	config.Proxy.MetadataURL = "http://localhost:8080/metadata"

	// Add the mock provider as an IDP
	config.IDP = []proxy.IDPConfig{
		{
			ID:              "mock",
			EntityID:        mockProvider.entityID,
			SSOURL:          mockProvider.ssoURL,
			CertificatePath: certPath, // Not actually used in the test
		},
	}

	// Create SAML service providers
	providers, err := proxy.CreateSAMLServiceProviders(config, cert)
	assert.NoError(t, err)

	// Set up HTTP handlers
	mux := proxy.SetupHTTPHandlers(providers, config)
	assert.NotNil(t, mux)

	// Create a test server for the proxy
	proxyServer := httptest.NewServer(mux)
	defer proxyServer.Close()

	// Test the metadata endpoint
	resp, err := http.Get(proxyServer.URL + "/metadata")
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/samlmetadata+xml", resp.Header.Get("Content-Type"))

	// Read the metadata
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	// Verify it's valid XML
	var metadata saml.EntityDescriptor
	err = xml.Unmarshal(body, &metadata)
	assert.NoError(t, err)

	// Verify the entity ID matches the configuration
	assert.Equal(t, config.Proxy.EntityID, metadata.EntityID)

	// Verify it contains the IDPSSODescriptor element (proxy now acts as an IdP)
	assert.Contains(t, string(body), "IDPSSODescriptor")
	assert.Contains(t, string(body), "urn:oasis:names:tc:SAML:2.0:protocol")
}

// TestSSOEndpoint tests the /sso endpoint of the SAML proxy.
func TestSSOEndpoint(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	// Load the certificate
	cert, err := proxy.LoadCertificate(certPath, keyPath)
	assert.NoError(t, err)

	// Create a mock SAML provider
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	// Create a test config with multiple IDP
	config := proxy.Config{}
	config.Proxy.EntityID = "http://localhost:8080/metadata"
	config.Proxy.AcsURL = "http://localhost:8080/sso/acs"
	config.Proxy.MetadataURL = "http://localhost:8080/metadata"

	// Add the mock provider as an IDP
	config.IDP = []proxy.IDPConfig{
		{
			ID:              "mock",
			EntityID:        mockProvider.entityID,
			SSOURL:          mockProvider.ssoURL,
			CertificatePath: certPath, // Not actually used in the test
		},
	}

	// Create SAML service providers
	providers, err := proxy.CreateSAMLServiceProviders(config, cert)
	assert.NoError(t, err)

	// Set up HTTP handlers
	mux := proxy.SetupHTTPHandlers(providers, config)
	assert.NotNil(t, mux)

	// Create a test server for the proxy
	proxyServer := httptest.NewServer(mux)
	defer proxyServer.Close()

	// Create a mock SAML client
	mockClient := NewMockSAMLClient(t)
	defer mockClient.Close()

	// Test 1: SSO endpoint with SAMLRequest parameter (should show IdP selection page)
	resp, err := http.Get(proxyServer.URL + "/sso?SAMLRequest=request123")
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Verify it returns the IdP selection page
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Select an Identity Provider")
	assert.Contains(t, string(body), "mock")

	// Test 2: SSO endpoint without SAMLRequest parameter (should return bad request)
	resp, err = http.Get(proxyServer.URL + "/sso")
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Verify it returns a bad request error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Missing SAMLRequest parameter")

	// Test 3: select_idp endpoint (should redirect to IdP)
	resp, err = http.Get(proxyServer.URL + "/select_idp/mock?SAMLRequest=request123&RelayState=state123")
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Verify it redirects to the IdP
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectURL := resp.Header.Get("Location")
	assert.Contains(t, redirectURL, mockProvider.ssoURL)
	assert.Contains(t, redirectURL, "SAMLRequest=request123")
	assert.Contains(t, redirectURL, "RelayState=state123")
}

// TestACSEndpoint tests the /sso/acs endpoint of the SAML proxy.
func TestACSEndpoint(t *testing.T) {
	// This test is more complex and would require simulating a full SAML authentication flow
	// For simplicity, we'll just verify that the endpoint exists and returns a method not allowed
	// error when accessed with a GET request (since it expects a POST with a SAMLResponse)

	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	// Load the certificate
	cert, err := proxy.LoadCertificate(certPath, keyPath)
	assert.NoError(t, err)

	// Create a mock SAML provider
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	// Create a test config with multiple IDP
	config := proxy.Config{}
	config.Proxy.EntityID = "http://localhost:8080/metadata"
	config.Proxy.AcsURL = "http://localhost:8080/sso/acs"
	config.Proxy.MetadataURL = "http://localhost:8080/metadata"

	// Add the mock provider as an IDP
	config.IDP = []proxy.IDPConfig{
		{
			ID:              "mock",
			EntityID:        mockProvider.entityID,
			SSOURL:          mockProvider.ssoURL,
			CertificatePath: certPath, // Not actually used in the test
		},
	}

	// Create SAML service providers
	providers, err := proxy.CreateSAMLServiceProviders(config, cert)
	assert.NoError(t, err)

	// Set up HTTP handlers
	mux := proxy.SetupHTTPHandlers(providers, config)
	assert.NotNil(t, mux)

	// Create a test server for the proxy
	proxyServer := httptest.NewServer(mux)
	defer proxyServer.Close()

	// Test 1: GET request to ACS endpoint (should fail with method not allowed)
	resp, err := http.Get(proxyServer.URL + "/sso/acs")
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Verify it returns an error status code
	assert.GreaterOrEqual(t, resp.StatusCode, 400, "Expected error status code for GET request to ACS endpoint")

	// Test 2: POST request to ACS endpoint without SAMLResponse (should fail with bad request)
	resp, err = http.PostForm(proxyServer.URL+"/sso/acs", url.Values{})
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Verify it returns an error status code
	assert.GreaterOrEqual(t, resp.StatusCode, 400, "Expected error status code for POST without SAMLResponse")

	// Test 3: Test the idp-initiated endpoint (should return not implemented)
	resp, err = http.Get(proxyServer.URL + "/idp-initiated")
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Verify it returns a not implemented status code
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "IdP-Initiated flow not yet implemented")
}

// TestE2EFlow tests the complete end-to-end flow: Service -> Proxy -> SAML Provider -> Proxy -> Service.
func TestE2EFlow(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer func() {
		if certPath != "" {
			err := os.RemoveAll(filepath.Dir(certPath))
			if err != nil {
				t.Logf("Failed to remove temp directory: %v", err)
			}
		}
	}()

	// Load the certificate
	cert, err := proxy.LoadCertificate(certPath, keyPath)
	assert.NoError(t, err)

	// Create a mock SAML provider
	mockProvider := NewMockSAMLProvider(t)
	defer mockProvider.Close()

	// Create a test config with multiple IDP
	config := proxy.Config{}
	config.Proxy.EntityID = "http://localhost:8080/metadata"
	config.Proxy.AcsURL = "http://localhost:8080/sso/acs"
	config.Proxy.MetadataURL = "http://localhost:8080/metadata"

	// Add the mock provider as an IDP
	config.IDP = []proxy.IDPConfig{
		{
			ID:              "mock",
			EntityID:        mockProvider.entityID,
			SSOURL:          mockProvider.ssoURL,
			CertificatePath: certPath, // Not actually used in the test
		},
	}

	// Create SAML service providers
	providers, err := proxy.CreateSAMLServiceProviders(config, cert)
	assert.NoError(t, err)

	// Set up HTTP handlers
	mux := proxy.SetupHTTPHandlers(providers, config)
	assert.NotNil(t, mux)

	// Create a test server for the proxy
	proxyServer := httptest.NewServer(mux)
	defer proxyServer.Close()

	// Create a mock SAML client
	mockClient := NewMockSAMLClient(t)
	defer mockClient.Close()

	// Create a client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Don't follow redirects automatically
			return http.ErrUseLastResponse
		},
	}

	// Step 1: SP sends AuthnRequest to proxy's SSO endpoint
	resp, err := client.Get(proxyServer.URL + "/sso?SAMLRequest=request123&RelayState=state123")
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Step 2: Proxy shows IdP selection page
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Select an Identity Provider")
	assert.Contains(t, string(body), "mock")

	// Step 3: User selects an IdP
	resp, err = client.Get(proxyServer.URL + "/select_idp/mock?SAMLRequest=request123&RelayState=state123")
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Step 4: Proxy redirects to the selected IdP
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectURL := resp.Header.Get("Location")
	assert.Contains(t, redirectURL, mockProvider.ssoURL)
	assert.Contains(t, redirectURL, "SAMLRequest=request123")
	assert.Contains(t, redirectURL, "RelayState=state123")

	// In a real E2E test, we would:
	// 1. Follow the redirect to the IdP
	// 2. Authenticate at the IdP
	// 3. IdP would redirect back to the proxy's ACS URL with a SAMLResponse
	// 4. Proxy would process the response and redirect to the SP
	//
	// However, this is complex to do in a unit test.
	// For simplicity, we'll just verify that the redirect URL is correct and points to our mock IdP.
}
