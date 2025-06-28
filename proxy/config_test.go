package proxy

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	// Save original environment
	origEnv := os.Environ()
	defer func() {
		// Restore original environment
		os.Clearenv()
		for _, env := range origEnv {
			key, value, _ := strings.Cut(env, "=")
			t.Setenv(key, value)
		}
	}()

	t.Run("Single IDP (Legacy Mode)", func(t *testing.T) {
		// Set up test environment variables for single IDP
		os.Clearenv()
		t.Setenv("PROXY_ENTITY_ID", "http://test.example.com/metadata")
		t.Setenv("PROXY_ACS_URL", "http://test.example.com/sso/acs")
		t.Setenv("PROXY_METADATA_URL", "http://test.example.com/metadata")
		t.Setenv("PROXY_PRIVATE_KEY_PATH", "/path/to/key.pem")
		t.Setenv("PROXY_CERTIFICATE_PATH", "/path/to/cert.pem")
		t.Setenv("PROXY_COOKIE_NAME", "test_idp_selection")
		t.Setenv("IDP_ID", "default")
		t.Setenv("IDP_ENTITY_ID", "https://idp.example.com/saml/metadata")
		t.Setenv("IDP_SSO_URL", "https://idp.example.com/saml/sso")
		t.Setenv("IDP_CERTIFICATE_PATH", "/path/to/idp.crt")
		t.Setenv("SERVER_LISTEN_ADDRESS", ":9090")

		// Test loading config
		config, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, "http://test.example.com/metadata", config.Proxy.EntityID)
		assert.Equal(t, "http://test.example.com/sso/acs", config.Proxy.AcsURL)
		assert.Equal(t, "http://test.example.com/metadata", config.Proxy.MetadataURL)
		assert.Equal(t, "/path/to/key.pem", config.Proxy.PrivateKeyPath)
		assert.Equal(t, "/path/to/cert.pem", config.Proxy.CertificatePath)
		assert.Equal(t, "test_idp_selection", config.Proxy.CookieName)

		// Verify the IDP was added to the IDPs slice
		assert.Len(t, config.IDPs, 1)
		assert.Equal(t, "default", config.IDPs[0].ID)
		assert.Equal(t, "https://idp.example.com/saml/metadata", config.IDPs[0].EntityID)
		assert.Equal(t, "https://idp.example.com/saml/sso", config.IDPs[0].SSOURL)
		assert.Equal(t, "/path/to/idp.crt", config.IDPs[0].CertificatePath)
		assert.Equal(t, ":9090", config.Server.ListenAddress)
	})

	t.Run("Multiple IDPs", func(t *testing.T) {
		// Set up test environment variables for multiple IDPs
		os.Clearenv()
		t.Setenv("PROXY_ENTITY_ID", "http://test.example.com/metadata")
		t.Setenv("PROXY_ACS_URL", "http://test.example.com/sso/acs")
		t.Setenv("PROXY_METADATA_URL", "http://test.example.com/metadata")
		t.Setenv("PROXY_PRIVATE_KEY_PATH", "/path/to/key.pem")
		t.Setenv("PROXY_CERTIFICATE_PATH", "/path/to/cert.pem")
		t.Setenv("PROXY_COOKIE_NAME", "test_idp_selection")

		// First IDP
		t.Setenv("IDP1_ID", "idp1")
		t.Setenv("IDP1_ENTITY_ID", "https://idp1.example.com/saml/metadata")
		t.Setenv("IDP1_SSO_URL", "https://idp1.example.com/saml/sso")
		t.Setenv("IDP1_CERTIFICATE_PATH", "/path/to/idp1.crt")

		// Second IDP
		t.Setenv("IDP2_ID", "idp2")
		t.Setenv("IDP2_ENTITY_ID", "https://idp2.example.com/saml/metadata")
		t.Setenv("IDP2_SSO_URL", "https://idp2.example.com/saml/sso")
		t.Setenv("IDP2_CERTIFICATE_PATH", "/path/to/idp2.crt")

		t.Setenv("SERVER_LISTEN_ADDRESS", ":9090")

		// Test loading config
		config, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, "http://test.example.com/metadata", config.Proxy.EntityID)
		assert.Equal(t, "http://test.example.com/sso/acs", config.Proxy.AcsURL)
		assert.Equal(t, "http://test.example.com/metadata", config.Proxy.MetadataURL)
		assert.Equal(t, "/path/to/key.pem", config.Proxy.PrivateKeyPath)
		assert.Equal(t, "/path/to/cert.pem", config.Proxy.CertificatePath)
		assert.Equal(t, "test_idp_selection", config.Proxy.CookieName)

		// Verify multiple IDPs were loaded
		assert.Len(t, config.IDPs, 2)

		// Sort IDPs by ID to ensure consistent order
		sort.Slice(config.IDPs, func(i, j int) bool {
			return config.IDPs[i].ID < config.IDPs[j].ID
		})

		// First IDP
		assert.Equal(t, "idp1", config.IDPs[0].ID)
		assert.Equal(t, "https://idp1.example.com/saml/metadata", config.IDPs[0].EntityID)
		assert.Equal(t, "https://idp1.example.com/saml/sso", config.IDPs[0].SSOURL)
		assert.Equal(t, "/path/to/idp1.crt", config.IDPs[0].CertificatePath)

		// Second IDP
		assert.Equal(t, "idp2", config.IDPs[1].ID)
		assert.Equal(t, "https://idp2.example.com/saml/metadata", config.IDPs[1].EntityID)
		assert.Equal(t, "https://idp2.example.com/saml/sso", config.IDPs[1].SSOURL)
		assert.Equal(t, "/path/to/idp2.crt", config.IDPs[1].CertificatePath)

		assert.Equal(t, ":9090", config.Server.ListenAddress)
	})

	t.Run("No IDP Configuration", func(t *testing.T) {
		// Set up test environment variables without any IDP
		os.Clearenv()
		t.Setenv("PROXY_ENTITY_ID", "http://test.example.com/metadata")
		t.Setenv("PROXY_ACS_URL", "http://test.example.com/sso/acs")
		t.Setenv("PROXY_METADATA_URL", "http://test.example.com/metadata")
		t.Setenv("PROXY_PRIVATE_KEY_PATH", "/path/to/key.pem")
		t.Setenv("PROXY_CERTIFICATE_PATH", "/path/to/cert.pem")
		t.Setenv("SERVER_LISTEN_ADDRESS", ":9090")

		// Test loading config - should fail because no IDP is configured
		_, err := LoadConfig()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one IDP must be configured")
	})
}
