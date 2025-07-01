package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProxyStorage(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)

	// Create a test config
	config := Config{}
	config.Proxy.CertificatePath = certPath
	config.Proxy.PrivateKeyPath = keyPath

	// Test creating a new ProxyStorage
	storage, err := NewProxyStorage(config)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.Equal(t, config, storage.config)
	assert.NotNil(t, storage.cert)
	assert.NotNil(t, storage.spCache)
	assert.NotNil(t, storage.authRequests)
	assert.NotNil(t, storage.entityIDByAppID)

	// Test with invalid certificate path
	invalidConfig := Config{}
	invalidConfig.Proxy.CertificatePath = "/nonexistent/cert.pem"
	invalidConfig.Proxy.PrivateKeyPath = "/nonexistent/key.pem"
	_, err = NewProxyStorage(invalidConfig)
	assert.Error(t, err)
}

func TestAuthRequest(t *testing.T) {
	// Create a test AuthRequest
	authRequest := &AuthRequest{
		ID:                       "test-id",
		ApplicationID:            "test-app-id",
		RelayState:               "test-relay-state",
		AccessConsumerServiceURL: "https://example.com/acs",
		BindingType:              "test-binding-type",
		AuthRequestID:            "test-auth-request-id",
		Issuer:                   "test-issuer",
		Destination:              "test-destination",
		UserID:                   "test-user-id",
		IsDone:                   true,
	}

	// Test getter methods
	assert.Equal(t, "test-id", authRequest.GetID())
	assert.Equal(t, "test-app-id", authRequest.GetApplicationID())
	assert.Equal(t, "test-relay-state", authRequest.GetRelayState())
	assert.Equal(t, "https://example.com/acs", authRequest.GetAccessConsumerServiceURL())
	assert.Equal(t, "test-binding-type", authRequest.GetBindingType())
	assert.Equal(t, "test-auth-request-id", authRequest.GetAuthRequestID())
	assert.Equal(t, "test-issuer", authRequest.GetIssuer())
	assert.Equal(t, "test-destination", authRequest.GetDestination())
	assert.Equal(t, "test-user-id", authRequest.GetUserID())
	assert.True(t, authRequest.Done())
}

func TestGetCertificateAndKey(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := generateTestCertificate(t)

	// Create a test config
	config := Config{}
	config.Proxy.CertificatePath = certPath
	config.Proxy.PrivateKeyPath = keyPath

	// Create a new ProxyStorage
	storage, err := NewProxyStorage(config)
	require.NoError(t, err)

	// Test getCertificateAndKey
	certAndKey, err := storage.getCertificateAndKey()
	require.NoError(t, err)
	assert.NotNil(t, certAndKey)
	assert.NotNil(t, certAndKey.Certificate)
	assert.NotNil(t, certAndKey.Key)
}
