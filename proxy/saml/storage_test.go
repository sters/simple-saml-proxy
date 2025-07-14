package saml

import (
	"fmt"
	"sync"
	"testing"
	"time"

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
	tests := []struct {
		name           string
		setupStorage   func() *Storage
		loginName      string
		expectedAttrs  map[string]string
		expectFallback bool
	}{
		{
			name: "Found auth request with full assertion data",
			setupStorage: func() *Storage {
				storage := &Storage{
					authRequests: make(map[string]*AuthRequest),
				}
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
				}
				storage.authRequests[authRequest.ID] = authRequest

				return storage
			},
			loginName: "john.doe@example.com",
			expectedAttrs: map[string]string{
				"UserID":    "john.doe@example.com",
				"Username":  "john.doe@example.com",
				"Email":     "john.doe@example.com",
				"FullName":  "John Doe",
				"GivenName": "John",
				"Surname":   "Doe",
			},
			expectFallback: false,
		},
		{
			name: "Found auth request with alternative attribute names",
			setupStorage: func() *Storage {
				storage := &Storage{
					authRequests: make(map[string]*AuthRequest),
				}
				authRequest := &AuthRequest{
					ID:     "test-auth-request",
					UserID: "jane.smith",
					Assertion: &saml.Assertion{
						Subject: &saml.Subject{
							NameID: &saml.NameID{
								Value: "jane.smith@company.com",
							},
						},
						AttributeStatements: []saml.AttributeStatement{
							{
								Attributes: []saml.Attribute{
									{
										Name: "Email", // Capital E
										Values: []saml.AttributeValue{
											{Value: "jane.smith@company.com"},
										},
									},
									{
										Name: "DisplayName", // Alternative name
										Values: []saml.AttributeValue{
											{Value: "Jane Smith"},
										},
									},
									{
										Name: "FirstName", // Alternative name
										Values: []saml.AttributeValue{
											{Value: "Jane"},
										},
									},
									{
										Name: "LastName", // Alternative name
										Values: []saml.AttributeValue{
											{Value: "Smith"},
										},
									},
								},
							},
						},
					},
				}
				storage.authRequests[authRequest.ID] = authRequest

				return storage
			},
			loginName: "jane.smith",
			expectedAttrs: map[string]string{
				"UserID":    "jane.smith@company.com",
				"Username":  "jane.smith@company.com",
				"Email":     "jane.smith@company.com",
				"FullName":  "Jane Smith",
				"GivenName": "Jane",
				"Surname":   "Smith",
			},
			expectFallback: false,
		},
		{
			name: "Found auth request with mail and sn attributes",
			setupStorage: func() *Storage {
				storage := &Storage{
					authRequests: make(map[string]*AuthRequest),
				}
				authRequest := &AuthRequest{
					ID:     "test-auth-request",
					UserID: "bob.jones",
					Assertion: &saml.Assertion{
						Subject: &saml.Subject{
							NameID: &saml.NameID{
								Value: "bob.jones",
							},
						},
						AttributeStatements: []saml.AttributeStatement{
							{
								Attributes: []saml.Attribute{
									{
										Name: "mail", // Alternative email attribute
										Values: []saml.AttributeValue{
											{Value: "bob@example.org"},
										},
									},
									{
										Name: "Name",
										Values: []saml.AttributeValue{
											{Value: "Bob Jones"},
										},
									},
									{
										Name: "GivenName",
										Values: []saml.AttributeValue{
											{Value: "Bob"},
										},
									},
									{
										Name: "sn", // LDAP-style surname
										Values: []saml.AttributeValue{
											{Value: "Jones"},
										},
									},
								},
							},
						},
					},
				}
				storage.authRequests[authRequest.ID] = authRequest

				return storage
			},
			loginName: "bob.jones",
			expectedAttrs: map[string]string{
				"UserID":    "bob.jones",
				"Username":  "bob.jones",
				"Email":     "bob@example.org",
				"FullName":  "Bob Jones",
				"GivenName": "Bob",
				"Surname":   "Jones",
			},
			expectFallback: false,
		},
		{
			name: "Found auth request but missing assertion",
			setupStorage: func() *Storage {
				storage := &Storage{
					authRequests: make(map[string]*AuthRequest),
				}
				authRequest := &AuthRequest{
					ID:        "test-auth-request",
					UserID:    "missing.assertion",
					Assertion: nil, // No assertion
				}
				storage.authRequests[authRequest.ID] = authRequest

				return storage
			},
			loginName: "missing.assertion",
			expectedAttrs: map[string]string{
				"UserID":    "missing.assertion",
				"Username":  "missing.assertion",
				"Email":     "missing.assertion@example.com",
				"FullName":  "Test User",
				"GivenName": "Test",
				"Surname":   "User",
			},
			expectFallback: true,
		},
		{
			name: "No matching auth request - fallback values",
			setupStorage: func() *Storage {
				storage := &Storage{
					authRequests: make(map[string]*AuthRequest),
				}
				// Add an auth request with different UserID
				authRequest := &AuthRequest{
					ID:     "test-auth-request",
					UserID: "other.user",
					Assertion: &saml.Assertion{
						Subject: &saml.Subject{
							NameID: &saml.NameID{
								Value: "other.user@example.com",
							},
						},
					},
				}
				storage.authRequests[authRequest.ID] = authRequest

				return storage
			},
			loginName: "unknown.user",
			expectedAttrs: map[string]string{
				"UserID":    "unknown.user",
				"Username":  "unknown.user",
				"Email":     "unknown.user@example.com",
				"FullName":  "Test User",
				"GivenName": "Test",
				"Surname":   "User",
			},
			expectFallback: true,
		},
		{
			name: "Empty storage - fallback values",
			setupStorage: func() *Storage {
				return &Storage{
					authRequests: make(map[string]*AuthRequest),
				}
			},
			loginName: "empty.storage",
			expectedAttrs: map[string]string{
				"UserID":    "empty.storage",
				"Username":  "empty.storage",
				"Email":     "empty.storage@example.com",
				"FullName":  "Test User",
				"GivenName": "Test",
				"Surname":   "User",
			},
			expectFallback: true,
		},
		{
			name: "Found auth request with empty attribute values",
			setupStorage: func() *Storage {
				storage := &Storage{
					authRequests: make(map[string]*AuthRequest),
				}
				authRequest := &AuthRequest{
					ID:     "test-auth-request",
					UserID: "empty.attrs",
					Assertion: &saml.Assertion{
						Subject: &saml.Subject{
							NameID: &saml.NameID{
								Value: "empty.attrs.user",
							},
						},
						AttributeStatements: []saml.AttributeStatement{
							{
								Attributes: []saml.Attribute{
									{
										Name:   "email",
										Values: []saml.AttributeValue{}, // Empty values
									},
									{
										Name: "name",
										Values: []saml.AttributeValue{
											{Value: ""}, // Empty string value
										},
									},
								},
							},
						},
					},
				}
				storage.authRequests[authRequest.ID] = authRequest

				return storage
			},
			loginName: "empty.attrs",
			expectedAttrs: map[string]string{
				"UserID":   "empty.attrs.user",
				"Username": "empty.attrs.user",
				"FullName": "", // Empty string value gets set
				// Email not set because Values array is empty
				// GivenName, Surname not included in attributes
			},
			expectFallback: false,
		},
		{
			name: "Multiple auth requests - finds correct one",
			setupStorage: func() *Storage {
				storage := &Storage{
					authRequests: make(map[string]*AuthRequest),
				}
				// Add multiple auth requests
				storage.authRequests["ar1"] = &AuthRequest{
					ID:     "ar1",
					UserID: "user1",
					Assertion: &saml.Assertion{
						Subject: &saml.Subject{
							NameID: &saml.NameID{
								Value: "user1@example.com",
							},
						},
					},
				}
				storage.authRequests["ar2"] = &AuthRequest{
					ID:     "ar2",
					UserID: "target.user",
					Assertion: &saml.Assertion{
						Subject: &saml.Subject{
							NameID: &saml.NameID{
								Value: "target@example.com",
							},
						},
						AttributeStatements: []saml.AttributeStatement{
							{
								Attributes: []saml.Attribute{
									{
										Name: "email",
										Values: []saml.AttributeValue{
											{Value: "target@example.com"},
										},
									},
								},
							},
						},
					},
				}
				storage.authRequests["ar3"] = &AuthRequest{
					ID:     "ar3",
					UserID: "user3",
					Assertion: &saml.Assertion{
						Subject: &saml.Subject{
							NameID: &saml.NameID{
								Value: "user3@example.com",
							},
						},
					},
				}

				return storage
			},
			loginName: "target.user",
			expectedAttrs: map[string]string{
				"UserID":   "target@example.com",
				"Username": "target@example.com",
				"Email":    "target@example.com",
			},
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := tt.setupStorage()
			userinfo := newMockAttributeSetter()

			err := storage.SetUserinfoWithLoginName(
				t.Context(),
				userinfo,
				tt.loginName,
				nil,
			)
			require.NoError(t, err)

			// Verify expected attributes
			for key, expectedValue := range tt.expectedAttrs {
				assert.Equal(t, expectedValue, userinfo.attributes[key], "Attribute %s mismatch", key)
			}

			// For attributes that might not be set (empty values case), check they don't exist
			if tt.name == "Found auth request with empty attribute values" {
				_, hasEmail := userinfo.attributes["Email"]
				assert.False(t, hasEmail, "Email should not be set when value is empty")
				// FullName will be set to empty string if the value is empty
				assert.Equal(t, "", userinfo.attributes["FullName"])
			}
		})
	}
}

func TestSetUserinfoWithLoginName_ConcurrentAccess(t *testing.T) {
	// Test concurrent access to ensure thread safety
	storage := &Storage{
		authRequests: make(map[string]*AuthRequest),
	}

	// Add multiple auth requests
	for i := range 10 {
		userID := fmt.Sprintf("user%d", i)
		storage.authRequests[fmt.Sprintf("ar%d", i)] = &AuthRequest{
			ID:     fmt.Sprintf("ar%d", i),
			UserID: userID,
			Assertion: &saml.Assertion{
				Subject: &saml.Subject{
					NameID: &saml.NameID{
						Value: userID + "@example.com",
					},
				},
			},
		}
	}

	// Run concurrent SetUserinfoWithLoginName calls
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			userinfo := newMockAttributeSetter()
			loginName := fmt.Sprintf("user%d", index)

			err := storage.SetUserinfoWithLoginName(
				t.Context(),
				userinfo,
				loginName,
				nil,
			)
			assert.NoError(t, err)
			assert.Equal(t, loginName+"@example.com", userinfo.attributes["UserID"])
		}(i)
	}

	wg.Wait()
}

func TestCleanupCompletedAuthRequests(t *testing.T) {
	// Create storage
	storage := &Storage{
		authRequests: make(map[string]*AuthRequest),
	}

	// Create auth requests with different completion times
	now := time.Now()

	// Completed and old (should be cleaned up)
	oldCompleted := &AuthRequest{
		ID:          "old-completed",
		IsDone:      true,
		CompletedAt: now.Add(-20 * time.Minute),
	}

	// Completed but recent (should not be cleaned up)
	recentCompleted := &AuthRequest{
		ID:          "recent-completed",
		IsDone:      true,
		CompletedAt: now.Add(-5 * time.Minute),
	}

	// Not completed (should not be cleaned up)
	notCompleted := &AuthRequest{
		ID:     "not-completed",
		IsDone: false,
	}

	// Completed but no timestamp (should not be cleaned up)
	completedNoTimestamp := &AuthRequest{
		ID:     "completed-no-timestamp",
		IsDone: true,
	}

	// Add all auth requests to storage
	storage.authRequests["old-completed"] = oldCompleted
	storage.authRequests["recent-completed"] = recentCompleted
	storage.authRequests["not-completed"] = notCompleted
	storage.authRequests["completed-no-timestamp"] = completedNoTimestamp

	// Run cleanup with 10 minute max age
	deleted := storage.CleanupCompletedAuthRequests(10 * time.Minute)

	// Verify results
	assert.Equal(t, 1, deleted, "Should have deleted 1 auth request")
	assert.Nil(t, storage.authRequests["old-completed"], "Old completed request should be deleted")
	assert.NotNil(t, storage.authRequests["recent-completed"], "Recent completed request should remain")
	assert.NotNil(t, storage.authRequests["not-completed"], "Not completed request should remain")
	assert.NotNil(t, storage.authRequests["completed-no-timestamp"], "Completed request without timestamp should remain")

	// Run cleanup again to verify idempotency
	deleted = storage.CleanupCompletedAuthRequests(10 * time.Minute)
	assert.Equal(t, 0, deleted, "No additional requests should be deleted")
}

func TestStorage_GetCA(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := GenerateTestCertificate(t)

	// Create a test config
	cfg := &config.Config{}
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Create a new Storage
	storage, err := NewStorage(*cfg)
	require.NoError(t, err)

	// Test GetCA
	certAndKey, err := storage.GetCA(t.Context())
	require.NoError(t, err)
	assert.NotNil(t, certAndKey)
	assert.NotNil(t, certAndKey.Certificate)
	assert.NotNil(t, certAndKey.Key)

	// Verify it returns the same certificate as getCertificateAndKey
	certAndKey2, err := storage.getCertificateAndKey()
	require.NoError(t, err)
	assert.Equal(t, certAndKey.Certificate, certAndKey2.Certificate)
	assert.Equal(t, certAndKey.Key, certAndKey2.Key)
}

func TestStorage_Health(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := GenerateTestCertificate(t)

	// Create a test config
	cfg := &config.Config{}
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath

	// Create a new Storage
	storage, err := NewStorage(*cfg)
	require.NoError(t, err)

	// Test Health - should always return nil
	err = storage.Health(t.Context())
	require.NoError(t, err)

	// Test Health multiple times to ensure consistency
	for range 5 {
		err = storage.Health(t.Context())
		assert.NoError(t, err)
	}
}

func TestStorage_GetAllowedSPs(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := GenerateTestCertificate(t)

	// Create test configs with different allowed SPs
	tests := []struct {
		name       string
		allowedSPs []config.SPConfig
	}{
		{
			name:       "No allowed SPs",
			allowedSPs: []config.SPConfig{},
		},
		{
			name: "Single allowed SP",
			allowedSPs: []config.SPConfig{
				{
					EntityID: "https://sp1.example.com",
				},
			},
		},
		{
			name: "Multiple allowed SPs",
			allowedSPs: []config.SPConfig{
				{
					EntityID: "https://sp1.example.com",
				},
				{
					EntityID: "https://sp2.example.com",
				},
				{
					EntityID: "https://sp3.example.com",
				},
			},
		},
		{
			name: "Allowed SPs with metadata URLs",
			allowedSPs: []config.SPConfig{
				{
					EntityID:    "https://sp1.example.com",
					MetadataURL: "https://sp1.example.com/metadata",
				},
				{
					EntityID:    "https://sp2.example.com",
					MetadataURL: "https://sp2.example.com/saml/metadata",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test config
			cfg := &config.Config{}
			cfg.Proxy.CertificatePath = certPath
			cfg.Proxy.PrivateKeyPath = keyPath
			cfg.Proxy.AllowedSP = tt.allowedSPs

			// Create a new Storage
			storage, err := NewStorage(*cfg)
			require.NoError(t, err)

			// Test GetAllowedSPs
			allowedSPs := storage.GetAllowedSPs()
			assert.Equal(t, tt.allowedSPs, allowedSPs)
			assert.Len(t, allowedSPs, len(tt.allowedSPs))

			// Verify each SP
			for i, sp := range allowedSPs {
				assert.Equal(t, tt.allowedSPs[i].EntityID, sp.EntityID)
				assert.Equal(t, tt.allowedSPs[i].MetadataURL, sp.MetadataURL)
			}
		})
	}
}

func TestStorage_GetAllowedSPs_Immutability(t *testing.T) {
	// Generate test certificate and key
	certPath, keyPath := GenerateTestCertificate(t)

	// Create a test config with allowed SPs
	cfg := &config.Config{}
	cfg.Proxy.CertificatePath = certPath
	cfg.Proxy.PrivateKeyPath = keyPath
	cfg.Proxy.AllowedSP = []config.SPConfig{
		{
			EntityID: "https://sp1.example.com",
		},
		{
			EntityID: "https://sp2.example.com",
		},
	}

	// Create a new Storage
	storage, err := NewStorage(*cfg)
	require.NoError(t, err)

	// Get allowed SPs
	allowedSPs1 := storage.GetAllowedSPs()
	allowedSPs2 := storage.GetAllowedSPs()

	// Both calls should return the same slice
	assert.Equal(t, allowedSPs1, allowedSPs2)

	// Verify the slice points to the same underlying data
	assert.Equal(t, len(cfg.Proxy.AllowedSP), len(allowedSPs1))
	for i := range allowedSPs1 {
		assert.Equal(t, cfg.Proxy.AllowedSP[i].EntityID, allowedSPs1[i].EntityID)
	}
}
