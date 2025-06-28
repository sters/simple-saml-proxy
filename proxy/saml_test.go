package proxy

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadCertificate(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer os.RemoveAll(filepath.Dir(certPath)) // Clean up temp directory

	// Test loading valid certificate
	cert, err := LoadCertificate(certPath, keyPath)
	require.NoError(t, err)
	assert.NotNil(t, cert.PrivateKey)
	assert.NotNil(t, cert.Leaf)

	// Verify it's a valid tls.Certificate
	var _ tls.Certificate = cert

	// Test loading invalid certificate
	_, err = LoadCertificate("/nonexistent/cert.pem", "/nonexistent/key.pem")
	assert.Error(t, err)
}

func TestCreateSAMLServiceProviders(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer os.RemoveAll(filepath.Dir(certPath)) // Clean up temp directory

	// Load the certificate
	cert, err := LoadCertificate(certPath, keyPath)
	require.NoError(t, err)

	t.Run("Single IDP", func(t *testing.T) {
		// Create a test config with a single IDP
		config := Config{}
		config.Proxy.EntityID = "http://test.example.com/metadata"

		// Add a single IDP
		config.IDP = []IDPConfig{
			{
				ID:              "idp1",
				EntityID:        "https://idp1.example.com/saml/metadata",
				SSOURL:          "https://idp1.example.com/saml/sso",
				CertificatePath: "/path/to/idp1.crt",
			},
		}

		// Test creating SAML service providers
		providers, err := CreateSAMLServiceProviders(config, cert)
		require.NoError(t, err)
		assert.NotNil(t, providers)

		// Verify the providers map contains the IDP
		assert.Len(t, providers.Providers, 1)
		assert.Contains(t, providers.Providers, "idp1")

		// Verify the default provider is set
		assert.NotNil(t, providers.Default)
		assert.Equal(t, "idp1", providers.Default.ID)

		// Verify the provider has the correct metadata
		provider := providers.Providers["idp1"]
		assert.Equal(t, "idp1", provider.ID)
		assert.NotNil(t, provider.Middleware)
		assert.Equal(t, "https://idp1.example.com/saml/metadata", provider.Middleware.ServiceProvider.IDPMetadata.EntityID)
	})

	t.Run("Multiple IDP", func(t *testing.T) {
		// Create a test config with multiple IDP
		config := Config{}
		config.Proxy.EntityID = "http://test.example.com/metadata"

		// Add multiple IDP
		config.IDP = []IDPConfig{
			{
				ID:              "idp1",
				EntityID:        "https://idp1.example.com/saml/metadata",
				SSOURL:          "https://idp1.example.com/saml/sso",
				CertificatePath: "/path/to/idp1.crt",
			},
			{
				ID:              "idp2",
				EntityID:        "https://idp2.example.com/saml/metadata",
				SSOURL:          "https://idp2.example.com/saml/sso",
				CertificatePath: "/path/to/idp2.crt",
			},
		}

		// Test creating SAML service providers
		providers, err := CreateSAMLServiceProviders(config, cert)
		require.NoError(t, err)
		assert.NotNil(t, providers)

		// Verify the providers map contains both IDP
		assert.Len(t, providers.Providers, 2)
		assert.Contains(t, providers.Providers, "idp1")
		assert.Contains(t, providers.Providers, "idp2")

		// Verify the default provider is set to the first IDP
		assert.NotNil(t, providers.Default)
		assert.Equal(t, "idp1", providers.Default.ID)

		// Verify the first provider has the correct metadata
		provider1 := providers.Providers["idp1"]
		assert.Equal(t, "idp1", provider1.ID)
		assert.NotNil(t, provider1.Middleware)
		assert.Equal(t, "https://idp1.example.com/saml/metadata", provider1.Middleware.ServiceProvider.IDPMetadata.EntityID)

		// Verify the second provider has the correct metadata
		provider2 := providers.Providers["idp2"]
		assert.Equal(t, "idp2", provider2.ID)
		assert.NotNil(t, provider2.Middleware)
		assert.Equal(t, "https://idp2.example.com/saml/metadata", provider2.Middleware.ServiceProvider.IDPMetadata.EntityID)
	})
}

func TestMustParseURL(t *testing.T) {
	// Test valid URL
	url := mustParseURL("http://example.com")
	assert.NotNil(t, url)
	assert.Equal(t, "http", url.Scheme)
	assert.Equal(t, "example.com", url.Host)

	// Test invalid URL (should panic)
	assert.Panics(t, func() {
		mustParseURL("://invalid-url")
	})
}
