package saml

import (
	"testing"

	"github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStorage(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := GenerateTestCertificate(t)

	// Create a test config
	cfg := &config.Config{}
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Test creating a new Storage
	storage, err := NewStorage(*cfg)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.Equal(t, *cfg, storage.config)
	assert.NotNil(t, storage.cert)
	assert.NotNil(t, storage.spCache)
	assert.NotNil(t, storage.authRequests)
	assert.NotNil(t, storage.entityIDByAppID)

	// Test with invalid certificate path
	invalidConfig := &config.Config{}
	invalidConfig.Proxy.CertificatePath = "/nonexistent/cert.pem"
	invalidConfig.Proxy.PrivateKeyPath = "/nonexistent/key.pem"
	_, err = NewStorage(*invalidConfig)
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
	certPath, keyPath := GenerateTestCertificate(t)

	// Create a test config
	cfg := &config.Config{}
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Create a new Storage
	storage, err := NewStorage(*cfg)
	require.NoError(t, err)

	// Test getCertificateAndKey
	certAndKey, err := storage.getCertificateAndKey()
	require.NoError(t, err)
	assert.NotNil(t, certAndKey)
	assert.NotNil(t, certAndKey.Certificate)
	assert.NotNil(t, certAndKey.Key)
}

// mockAttributeSetter implements models.AttributeSetter for testing.
type mockAttributeSetter struct {
	attributes map[string]string
}

func newMockAttributeSetter() *mockAttributeSetter {
	return &mockAttributeSetter{
		attributes: make(map[string]string),
	}
}

func (m *mockAttributeSetter) SetUserID(id string) {
	m.attributes["UserID"] = id
}

func (m *mockAttributeSetter) SetUsername(username string) {
	m.attributes["Username"] = username
}

func (m *mockAttributeSetter) SetEmail(email string) {
	m.attributes["Email"] = email
}

func (m *mockAttributeSetter) SetFullName(name string) {
	m.attributes["FullName"] = name
}

func (m *mockAttributeSetter) SetGivenName(name string) {
	m.attributes["GivenName"] = name
}

func (m *mockAttributeSetter) SetSurname(name string) {
	m.attributes["Surname"] = name
}

func (m *mockAttributeSetter) SetCustomAttribute(name, _, _ string, attributeValue []string) {
	if len(attributeValue) > 0 {
		m.attributes[name] = attributeValue[0]
	}
}

func TestSetUserinfoWithUserID_AssertionData(t *testing.T) {
	tests := []struct {
		name               string
		assertion          *saml.Assertion
		expectedAttributes map[string]string
	}{
		{
			name: "Standard attribute names",
			assertion: &saml.Assertion{
				Subject: &saml.Subject{
					NameID: &saml.NameID{
						Value: "john.doe@example.com",
					},
				},
				AttributeStatements: []saml.AttributeStatement{
					{
						Attributes: []saml.Attribute{
							{
								Name: "email",
								Values: []saml.AttributeValue{
									{Value: "john.doe@example.com"},
								},
							},
							{
								Name: "name",
								Values: []saml.AttributeValue{
									{Value: "John Doe"},
								},
							},
							{
								Name: "givenName",
								Values: []saml.AttributeValue{
									{Value: "John"},
								},
							},
							{
								Name: "surname",
								Values: []saml.AttributeValue{
									{Value: "Doe"},
								},
							},
						},
					},
				},
			},
			expectedAttributes: map[string]string{
				"UserID":    "john.doe@example.com",
				"Username":  "john.doe@example.com",
				"Email":     "john.doe@example.com",
				"FullName":  "John Doe",
				"GivenName": "John",
				"Surname":   "Doe",
			},
		},
		{
			name: "Alternative attribute names",
			assertion: &saml.Assertion{
				Subject: &saml.Subject{
					NameID: &saml.NameID{
						Value: "jane.smith@example.com",
					},
				},
				AttributeStatements: []saml.AttributeStatement{
					{
						Attributes: []saml.Attribute{
							{
								Name: "mail",
								Values: []saml.AttributeValue{
									{Value: "jane.smith@example.com"},
								},
							},
							{
								Name: "displayName",
								Values: []saml.AttributeValue{
									{Value: "Jane Smith"},
								},
							},
							{
								Name: "firstName",
								Values: []saml.AttributeValue{
									{Value: "Jane"},
								},
							},
							{
								Name: "lastName",
								Values: []saml.AttributeValue{
									{Value: "Smith"},
								},
							},
						},
					},
				},
			},
			expectedAttributes: map[string]string{
				"UserID":    "jane.smith@example.com",
				"Username":  "jane.smith@example.com",
				"Email":     "jane.smith@example.com",
				"FullName":  "Jane Smith",
				"GivenName": "Jane",
				"Surname":   "Smith",
			},
		},
		{
			name:      "No assertion data - fallback",
			assertion: nil,
			expectedAttributes: map[string]string{
				"UserID":    "test-user",
				"Username":  "test-user",
				"Email":     "test-user@example.com",
				"FullName":  "Test User",
				"GivenName": "Test",
				"Surname":   "User",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create storage
			storage := &Storage{
				authRequests: make(map[string]*AuthRequest),
			}

			// Create auth request with assertion
			authRequest := &AuthRequest{
				ID:        "test-auth-request",
				UserID:    "test-user",
				Assertion: tt.assertion,
			}

			// Add to storage
			storage.authRequests[authRequest.ID] = authRequest

			// Create mock attribute setter
			userinfo := newMockAttributeSetter()

			// Call SetUserinfoWithUserID
			err := storage.SetUserinfoWithUserID(
				t.Context(),
				authRequest.ID,
				userinfo,
				"test-user",
				nil,
			)
			require.NoError(t, err)

			// Verify attributes
			for key, expectedValue := range tt.expectedAttributes {
				assert.Equal(t, expectedValue, userinfo.attributes[key],
					"Attribute %s should be %s", key, expectedValue)
			}
		})
	}
}

func TestSetUserinfoWithLoginName_AssertionData(t *testing.T) {
	// Create storage
	storage := &Storage{
		authRequests: make(map[string]*AuthRequest),
	}

	// Create auth request with assertion
	authRequest := &AuthRequest{
		ID:     "test-auth-request",
		UserID: "john.doe@example.com",
		Assertion: &saml.Assertion{
			Subject: &saml.Subject{
				NameID: &saml.NameID{
					Value: "john.doe@example.com",
				},
			},
			AttributeStatements: []saml.AttributeStatement{
				{
					Attributes: []saml.Attribute{
						{
							Name: "email",
							Values: []saml.AttributeValue{
								{Value: "john.doe@example.com"},
							},
						},
						{
							Name: "name",
							Values: []saml.AttributeValue{
								{Value: "John Doe"},
							},
						},
					},
				},
			},
		},
	}

	// Add to storage
	storage.authRequests[authRequest.ID] = authRequest

	// Create mock attribute setter
	userinfo := newMockAttributeSetter()

	// Call SetUserinfoWithLoginName
	err := storage.SetUserinfoWithLoginName(
		t.Context(),
		userinfo,
		"john.doe@example.com",
		nil,
	)
	require.NoError(t, err)

	// Verify attributes
	assert.Equal(t, "john.doe@example.com", userinfo.attributes["UserID"])
	assert.Equal(t, "john.doe@example.com", userinfo.attributes["Username"])
	assert.Equal(t, "john.doe@example.com", userinfo.attributes["Email"])
	assert.Equal(t, "John Doe", userinfo.attributes["FullName"])
}
