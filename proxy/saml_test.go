package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
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

func TestCreateProxyIDP(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer os.RemoveAll(filepath.Dir(certPath)) // Clean up temp directory

	// Create a test config
	config := Config{}
	config.Proxy.EntityID = "http://test.example.com/metadata"
	config.Proxy.AcsURL = "http://test.example.com/sso/acs"
	config.Proxy.MetadataURL = "http://test.example.com/metadata"
	config.Proxy.CertificatePath = certPath
	config.Proxy.PrivateKeyPath = keyPath

	// Add a single IDP
	config.IDP = []IDPConfig{
		{
			ID:              "idp1",
			EntityID:        "https://idp1.example.com/saml/metadata",
			SSOURL:          "https://idp1.example.com/saml/sso",
			CertificatePath: certPath, // Use the same cert for testing
		},
	}

	// Test creating proxy IDP
	idp, err := CreateProxyIDP(config)
	require.NoError(t, err)
	assert.NotNil(t, idp)
	assert.Equal(t, config.Proxy.EntityID, idp.EntityID)
	assert.NotNil(t, idp.idp)
	assert.NotNil(t, idp.idpStorage)

	// Test with invalid certificate path
	invalidConfig := Config{}
	invalidConfig.Proxy.EntityID = "http://test.example.com/metadata"
	invalidConfig.Proxy.CertificatePath = "/nonexistent/cert.pem"
	invalidConfig.Proxy.PrivateKeyPath = "/nonexistent/key.pem"
	invalidConfig.IDP = []IDPConfig{
		{
			ID:              "idp1",
			EntityID:        "https://idp1.example.com/saml/metadata",
			SSOURL:          "https://idp1.example.com/saml/sso",
			CertificatePath: certPath,
		},
	}

	_, err = CreateProxyIDP(invalidConfig)
	assert.Error(t, err)
}

func TestServiceProvidersGetProvider(t *testing.T) {
	// Create test service providers
	providers := &ServiceProviders{
		Providers: make(map[string]*ServiceProvider),
	}

	// Add providers
	providers.Providers["idp1"] = &ServiceProvider{ID: "idp1"}
	providers.Providers["idp2"] = &ServiceProvider{ID: "idp2"}
	providers.Default = providers.Providers["idp1"]

	// Test getting provider by ID
	provider := providers.GetProvider("idp1")
	assert.NotNil(t, provider)
	assert.Equal(t, "idp1", provider.ID)

	provider = providers.GetProvider("idp2")
	assert.NotNil(t, provider)
	assert.Equal(t, "idp2", provider.ID)

	// Test getting default provider
	provider = providers.GetProvider("")
	assert.NotNil(t, provider)
	assert.Equal(t, "idp1", provider.ID)

	// Test getting non-existent provider (should return default)
	provider = providers.GetProvider("nonexistent")
	assert.NotNil(t, provider)
	assert.Equal(t, "idp1", provider.ID)
}

func TestCreateServiceProviders(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)
	defer os.RemoveAll(filepath.Dir(certPath)) // Clean up temp directory

	t.Run("Single IDP", func(t *testing.T) {
		// Create a test config with a single IDP
		config := Config{}
		config.Proxy.EntityID = "http://test.example.com/metadata"
		config.Proxy.CertificatePath = certPath
		config.Proxy.PrivateKeyPath = keyPath

		// Add a single IDP
		config.IDP = []IDPConfig{
			{
				ID:              "idp1",
				EntityID:        "https://idp1.example.com/saml/metadata",
				SSOURL:          "https://idp1.example.com/saml/sso",
				CertificatePath: certPath, // Use the same cert for testing
			},
		}

		// Test creating SAML service providers
		providers, err := CreateServiceProviders(t.Context(), config)
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
		config.Proxy.CertificatePath = certPath
		config.Proxy.PrivateKeyPath = keyPath

		// Add multiple IDP
		config.IDP = []IDPConfig{
			{
				ID:              "idp1",
				EntityID:        "https://idp1.example.com/saml/metadata",
				SSOURL:          "https://idp1.example.com/saml/sso",
				CertificatePath: certPath, // Use the same cert for testing
			},
			{
				ID:              "idp2",
				EntityID:        "https://idp2.example.com/saml/metadata",
				SSOURL:          "https://idp2.example.com/saml/sso",
				CertificatePath: certPath, // Use the same cert for testing
			},
		}

		// Test creating SAML service providers
		providers, err := CreateServiceProviders(t.Context(), config)
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

	t.Run("IDP with MetadataURL", func(t *testing.T) {
		// Create a mock HTTP server to serve metadata
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simplified metadata response
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://metadata-idp.example.com/saml/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt
eXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw
NjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U
erkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8
G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q
LdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF
2p1MA6pVW2gjmywdVL+HObxx9o3FaX8cpZLldECBZKSEizN7AlNoEwQRSJNbvPbw
jdgdKQvGTYFVXXIkpILLbCCm/TIkLT9c3JZoiJNFY6XqCRn75oJRAgMBAAEwDQYJ
KoZIhvcNAQELBQADggEBAJxFXh7I4oakHLzKgBsUDP2yCJIrloUuX4NtOuoSuzYt
U0MnI3WZ5Xa8XGtEE/0oM2yfMgC6omX1JtFQILmAKfC8roAUOZXQTWX9R+DYrOu2
I9Ro8PtNn7KGfBRTm8X5LbQnXX3pGYVnYaQiPxXF1UqdAYNsuYQCRWxAzVNlGNBk
C/5Vvm4j+qbAqKz1wLMKlAuiYlkBaFzsMvWyKC5A0bQaM13rXJu9sJwlIR2WQxwJ
lKl7jKg5n2PVL2kBF8CxHHY3JpqNf+uRWxJHvKGUYCb+r+7+esCv8ZrgCCuUjXXE
m1rhMtZCwLf9bUG8OkZRnZEMIagLIPRpwVd6JvjYWp8=</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://metadata-idp.example.com/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`))
		}))
		defer server.Close()

		// Create a test config with IDP using MetadataURL
		config := Config{}
		config.Proxy.EntityID = "http://test.example.com/metadata"
		config.Proxy.CertificatePath = certPath
		config.Proxy.PrivateKeyPath = keyPath

		// Add IDP with MetadataURL
		config.IDP = []IDPConfig{
			{
				ID:          "metadata-idp",
				MetadataURL: server.URL,
			},
		}

		// Test creating SAML service providers
		providers, err := CreateServiceProviders(t.Context(), config)
		require.NoError(t, err)
		assert.NotNil(t, providers)

		// Verify the providers map contains the IDP
		assert.Len(t, providers.Providers, 1)
		assert.Contains(t, providers.Providers, "metadata-idp")

		// Verify the provider has the correct metadata
		provider := providers.Providers["metadata-idp"]
		assert.Equal(t, "metadata-idp", provider.ID)
		assert.NotNil(t, provider.Middleware)
		assert.Equal(t, "https://metadata-idp.example.com/saml/metadata", provider.Middleware.ServiceProvider.IDPMetadata.EntityID)
	})

	t.Run("Invalid Certificate Path", func(t *testing.T) {
		// Create a test config with invalid certificate path
		config := Config{}
		config.Proxy.EntityID = "http://test.example.com/metadata"
		config.Proxy.CertificatePath = "/nonexistent/cert.pem"
		config.Proxy.PrivateKeyPath = "/nonexistent/key.pem"

		// Add a single IDP
		config.IDP = []IDPConfig{
			{
				ID:              "idp1",
				EntityID:        "https://idp1.example.com/saml/metadata",
				SSOURL:          "https://idp1.example.com/saml/sso",
				CertificatePath: certPath,
			},
		}

		// Test creating SAML service providers - should fail
		_, err := CreateServiceProviders(t.Context(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load certificate and key")
	})
}
