package proxy

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/zitadel/saml/pkg/provider/key"
	"github.com/zitadel/saml/pkg/provider/models"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

// ProxyStorage implements the zitadel/saml Storage interfaces.
type ProxyStorage struct {
	config Config
	cert   tls.Certificate

	// Cache for service providers
	spCache     map[string]*serviceprovider.ServiceProvider
	spCacheLock sync.RWMutex

	// Cache for auth requests
	authRequests     map[string]*AuthRequest
	authRequestsLock sync.RWMutex

	entityIDByAppID     map[string]string
	entityIDByAppIDLock sync.RWMutex
}

// NewProxyStorage creates a new ProxyStorage.
func NewProxyStorage(config Config) (*ProxyStorage, error) {
	cert, err := LoadCertificate(config.Proxy.CertificatePath, config.Proxy.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	return &ProxyStorage{
		config:          config,
		cert:            cert,
		spCache:         make(map[string]*serviceprovider.ServiceProvider),
		authRequests:    make(map[string]*AuthRequest),
		entityIDByAppID: make(map[string]string),
	}, nil
}

// AuthRequest implements the models.AuthRequestInt interface.
type AuthRequest struct {
	ID                       string
	ApplicationID            string
	RelayState               string
	AccessConsumerServiceURL string
	BindingType              string
	AuthRequestID            string
	Issuer                   string
	Destination              string
	UserID                   string
	IsDone                   bool
}

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetApplicationID() string {
	return a.ApplicationID
}

func (a *AuthRequest) GetRelayState() string {
	return a.RelayState
}

func (a *AuthRequest) GetAccessConsumerServiceURL() string {
	return a.AccessConsumerServiceURL
}

func (a *AuthRequest) GetBindingType() string {
	return a.BindingType
}

func (a *AuthRequest) GetAuthRequestID() string {
	return a.AuthRequestID
}

func (a *AuthRequest) GetIssuer() string {
	return a.Issuer
}

func (a *AuthRequest) GetDestination() string {
	return a.Destination
}

func (a *AuthRequest) GetUserID() string {
	return a.UserID
}

func (a *AuthRequest) Done() bool {
	return a.IsDone
}

// EntityStorage interface implementation

func (s *ProxyStorage) GetCA(ctx context.Context) (*key.CertificateAndKey, error) {
	// For simplicity, we'll use the same certificate for CA, metadata signing, and response signing
	return s.getCertificateAndKey()
}

func (s *ProxyStorage) GetMetadataSigningKey(ctx context.Context) (*key.CertificateAndKey, error) {
	return s.getCertificateAndKey()
}

// IdentityProviderStorage interface implementation

func (s *ProxyStorage) GetEntityByID(ctx context.Context, entityID string) (*serviceprovider.ServiceProvider, error) {
	s.spCacheLock.RLock()
	sp, ok := s.spCache[entityID]
	s.spCacheLock.RUnlock()

	if ok {
		return sp, nil
	}

	// If not in cache, create a new one
	for _, allowedSP := range s.config.Proxy.AllowedSP {
		if allowedSP.EntityID == entityID {
			// Create a service provider config for requester info
			var metadataBytes []byte
			if allowedSP.MetadataURL != "" {
				b, err := xml.ReadMetadataFromURL(http.DefaultClient, allowedSP.MetadataURL)
				if err != nil {
					return nil, fmt.Errorf("failed to read metadata from URL: %w", err)
				}
				metadataBytes = b
			} else {
				metadataBytes = []byte("<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='" + entityID + "'></EntityDescriptor>")
			}

			parsedMetadata, err := xml.ParseMetadataXmlIntoStruct(metadataBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse metadata: %w", err)
			}
			spConfig := &serviceprovider.Config{
				Metadata: metadataBytes,
			}

			// loginURL for Proxy IdP (Not for SP, Not for actual IdP)
			loginURL := func(id string) string {
				slog.Info("login URL", slog.String("id", id))

				return "/idp_select?id=" + id
			}

			// Create a new service provider
			sp, err := serviceprovider.NewServiceProvider(parsedMetadata.Id, spConfig, loginURL)
			if err != nil {
				return nil, fmt.Errorf("failed to create service provider: %w", err)
			}

			// Cache the service provider
			s.spCacheLock.Lock()
			s.spCache[entityID] = sp
			s.spCacheLock.Unlock()

			return sp, nil
		}
	}

	return nil, fmt.Errorf("entity not found: %s", entityID)
}

func (s *ProxyStorage) GetEntityIDByAppID(ctx context.Context, appID string) (string, error) {
	s.entityIDByAppIDLock.RLock()
	entityID, ok := s.entityIDByAppID[appID]
	s.entityIDByAppIDLock.RUnlock()

	if !ok {
		return "", fmt.Errorf("entity not found: %s", appID)
	}

	return entityID, nil
}

func (s *ProxyStorage) GetResponseSigningKey(ctx context.Context) (*key.CertificateAndKey, error) {
	return s.getCertificateAndKey()
}

// AuthStorage interface implementation

func (s *ProxyStorage) CreateAuthRequest(ctx context.Context, authnRequest *samlp.AuthnRequestType, appID, bindingType, relayState, userID string) (models.AuthRequestInt, error) {
	id := uuid.New().String()

	authRequest := &AuthRequest{
		ID:                       id,
		ApplicationID:            appID,
		RelayState:               relayState,
		AccessConsumerServiceURL: authnRequest.AssertionConsumerServiceURL,
		BindingType:              bindingType,
		AuthRequestID:            authnRequest.Id,
		Issuer:                   authnRequest.Issuer.Text,
		Destination:              authnRequest.Destination,
		UserID:                   userID,
		IsDone:                   false,
	}

	s.authRequestsLock.Lock()
	s.authRequests[id] = authRequest
	s.authRequestsLock.Unlock()

	s.entityIDByAppIDLock.Lock()
	s.entityIDByAppID[appID] = authnRequest.Issuer.Text
	s.entityIDByAppIDLock.Unlock()

	return authRequest, nil
}

func (s *ProxyStorage) AuthRequestByID(ctx context.Context, id string) (models.AuthRequestInt, error) {
	s.authRequestsLock.RLock()
	authRequest, ok := s.authRequests[id]
	s.authRequestsLock.RUnlock()

	if !ok {
		return nil, fmt.Errorf("auth request not found: %s", id)
	}

	return authRequest, nil
}

// UserStorage interface implementation

func (s *ProxyStorage) SetUserinfoWithUserID(ctx context.Context, applicationID string, userinfo models.AttributeSetter, userID string, attributes []int) (err error) {
	// TODO: Set user attributes
	userinfo.SetUserID(userID)
	userinfo.SetUsername(userID)
	userinfo.SetEmail(userID + "@example.com")
	userinfo.SetFullName("Test User")
	userinfo.SetGivenName("Test")
	userinfo.SetSurname("User")

	return nil
}

func (s *ProxyStorage) SetUserinfoWithLoginName(ctx context.Context, userinfo models.AttributeSetter, loginName string, attributes []int) (err error) {
	// TODO: Set user attributes
	userinfo.SetUserID(loginName)
	userinfo.SetUsername(loginName)
	userinfo.SetEmail(loginName + "@example.com")
	userinfo.SetFullName("Test User")
	userinfo.SetGivenName("Test")
	userinfo.SetSurname("User")

	return nil
}

func (s *ProxyStorage) Health(ctx context.Context) error {
	return nil
}

// Helper methods

func (s *ProxyStorage) getCertificateAndKey() (*key.CertificateAndKey, error) {
	// Extract the certificate and private key from the tls.Certificate
	if s.cert.PrivateKey == nil {
		return nil, errors.New("private key is nil")
	}

	privateKey, ok := s.cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}

	return &key.CertificateAndKey{
		Certificate: s.cert.Certificate[0],
		Key:         privateKey,
	}, nil
}
