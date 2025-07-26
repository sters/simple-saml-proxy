package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/zitadel/saml/pkg/provider/key"
	"github.com/zitadel/saml/pkg/provider/models"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

var (
	ErrPrivateKeyIsNil        = errors.New("private key is nil")
	ErrPrivateKeyNotRSA       = errors.New("private key is not an RSA key")
	ErrEntityNotFound         = errors.New("entity not found")
	ErrAuthRequestNotFound    = errors.New("auth request not found")
	ErrInvalidAuthRequestType = errors.New("invalid auth request type")
	ErrLogoutContextNotFound  = errors.New("logout context not found")
	ErrNoSPSSODescriptor      = errors.New("no SPSSODescriptor found in metadata")
	ErrNoSingleLogoutService  = errors.New("no SingleLogoutService found in metadata")
)

// Storage implements the zitadel/saml Storage interfaces.
type Storage struct {
	config config.Config
	cert   tls.Certificate

	// Cache for service providers
	spCache     map[string]*serviceprovider.ServiceProvider
	spCacheLock sync.RWMutex

	// Cache for SP certificates
	spCertCache *SPCertificateCache

	// Cache for auth requests
	authRequests     map[string]*AuthRequest
	authRequestsLock sync.RWMutex

	entityIDByAppID     map[string]string
	entityIDByAppIDLock sync.RWMutex

	// Cache for logout contexts
	logoutContexts     map[string]*LogoutContext
	logoutContextsLock sync.RWMutex
}

// SingleLogoutService represents a parsed SingleLogoutService endpoint from SP metadata.
type SingleLogoutService struct {
	Binding          string
	Location         string
	ResponseLocation string // Optional response location (if different from Location)
}

// NewStorage creates a new Storage.
func NewStorage(cfg config.Config) (*Storage, error) {
	cert, err := LoadCertificate(cfg.Proxy.CertificatePath, cfg.Proxy.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	return &Storage{
		config:          cfg,
		cert:            cert,
		spCache:         make(map[string]*serviceprovider.ServiceProvider),
		spCertCache:     NewSPCertificateCache(),
		authRequests:    make(map[string]*AuthRequest),
		entityIDByAppID: make(map[string]string),
		logoutContexts:  make(map[string]*LogoutContext),
	}, nil
}

// EntityStorage interface implementation

func (s *Storage) GetCA(_ context.Context) (*key.CertificateAndKey, error) {
	// For simplicity, we'll use the same certificate for CA, metadata signing, and response signing
	return s.getCertificateAndKey()
}

func (s *Storage) GetMetadataSigningKey(_ context.Context) (*key.CertificateAndKey, error) {
	return s.getCertificateAndKey()
}

// IdentityProviderStorage interface implementation

func (s *Storage) GetEntityByID(ctx context.Context, entityID string) (*serviceprovider.ServiceProvider, error) {
	s.spCacheLock.RLock()
	sp, ok := s.spCache[entityID]
	s.spCacheLock.RUnlock()

	if ok {
		return sp, nil
	}

	// If not in cache, create a new one
	for _, allowedSP := range s.config.Proxy.AllowedSP {
		if allowedSP.EntityID != entityID {
			continue
		}

		// Create a service provider config for requester info
		var metadataBytes []byte
		if allowedSP.MetadataURL != "" {
			b, err := ReadMetadataFromURLWithRetry(ctx, http.DefaultClient, allowedSP.MetadataURL, s.config)
			if err != nil {
				return nil, fmt.Errorf("failed to read metadata from URL: %w", err)
			}
			metadataBytes = b
		} else {
			// Create a minimal but valid metadata for SP without a metadata URL
			metadataBytes = []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">
				<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + entityID + `/acs" index="0"/>
				</SPSSODescriptor>
			</EntityDescriptor>`)
		}

		// Validate the metadata can be parsed
		_, err := xml.ParseMetadataXmlIntoStruct(metadataBytes)
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
		sp, err := serviceprovider.NewServiceProvider(entityID, spConfig, loginURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create service provider: %w", err)
		}

		// Cache the service provider
		s.spCacheLock.Lock()
		s.spCache[entityID] = sp
		s.spCacheLock.Unlock()

		return sp, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrEntityNotFound, entityID)
}

func (s *Storage) GetEntityIDByAppID(_ context.Context, appID string) (string, error) {
	s.entityIDByAppIDLock.RLock()
	entityID, ok := s.entityIDByAppID[appID]
	s.entityIDByAppIDLock.RUnlock()

	if !ok {
		return "", fmt.Errorf("%w: %s", ErrEntityNotFound, appID)
	}

	return entityID, nil
}

// SetEntityIDMapping sets the entity ID mapping for an app ID.
func (s *Storage) SetEntityIDMapping(appID, entityID string) {
	s.entityIDByAppIDLock.Lock()
	s.entityIDByAppID[appID] = entityID
	s.entityIDByAppIDLock.Unlock()
}

func (s *Storage) GetResponseSigningKey(_ context.Context) (*key.CertificateAndKey, error) {
	return s.getCertificateAndKey()
}

// AuthStorage interface implementation

//nolint:ireturn,lll // Required by interface
func (s *Storage) CreateAuthRequest(_ context.Context, authnRequest *samlp.AuthnRequestType, appID, bindingType, relayState, userID string) (models.AuthRequestInt, error) {
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
	// Also store by ACS URL for zitadel/saml library compatibility
	acsURL := s.config.Proxy.AcsURL
	if acsURL != "" {
		s.authRequests[acsURL] = authRequest
		slog.Info("Stored auth request by ACS URL", slog.String("url", acsURL), slog.String("id", id))
	}
	s.authRequestsLock.Unlock()

	s.entityIDByAppIDLock.Lock()
	s.entityIDByAppID[appID] = authnRequest.Issuer.Text
	s.entityIDByAppIDLock.Unlock()

	return authRequest, nil
}

//nolint:ireturn // Required by interface
func (s *Storage) AuthRequestByID(_ context.Context, id string) (models.AuthRequestInt, error) {
	s.authRequestsLock.RLock()
	authRequest, ok := s.authRequests[id]
	s.authRequestsLock.RUnlock()

	if !ok {
		// If not found by ID, try to find by URL (for zitadel/saml library compatibility)
		slog.Info("Auth request not found by ID, trying by URL", slog.String("id", id))
		s.authRequestsLock.RLock()
		authRequest, ok = s.authRequests[id] // id might be a URL
		s.authRequestsLock.RUnlock()

		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrAuthRequestNotFound, id)
		}
		slog.Info("Found auth request by URL", slog.String("url", id))
	}

	return authRequest, nil
}

// UserStorage interface implementation

func (s *Storage) SetUserinfoWithUserID(
	ctx context.Context,
	authRequestID string,
	userinfo models.AttributeSetter,
	userID string,
	_ []int,
) error {
	// Get the auth request to retrieve the assertion
	authRequestInt, err := s.AuthRequestByID(ctx, authRequestID)
	if err != nil {
		slog.Error("Failed to get auth request", slog.String("error", err.Error()))

		return err
	}

	authRequest, ok := authRequestInt.(*AuthRequest)
	if !ok {
		slog.Error("Failed to cast auth request")

		return ErrInvalidAuthRequestType
	}

	// Use assertion data if available
	if authRequest.Assertion == nil || authRequest.Assertion.Subject == nil {
		// Fallback to original behavior if no assertion is available
		slog.Warn("No assertion data available, using fallback values")
		userinfo.SetUserID(userID)
		userinfo.SetUsername(userID)
		userinfo.SetEmail(userID + "@example.com")
		userinfo.SetFullName("Test User")
		userinfo.SetGivenName("Test")
		userinfo.SetSurname("User")

		return nil
	}

	// Process user attributes from the assertion
	s.processUserAttributes(userinfo, authRequest.Assertion)

	return nil
}

func (s *Storage) SetUserinfoWithLoginName(
	_ context.Context,
	userinfo models.AttributeSetter,
	loginName string,
	_ []int,
) error {
	// For login name, we don't have access to the auth request ID,
	// so we need to find the auth request by user ID
	// This is a limitation of the current design

	// Try to find an auth request with matching UserID
	s.authRequestsLock.RLock()
	var foundAuthRequest *AuthRequest
	for _, ar := range s.authRequests {
		if ar.UserID == loginName && ar.Assertion != nil {
			foundAuthRequest = ar

			break
		}
	}
	s.authRequestsLock.RUnlock()

	if foundAuthRequest == nil || foundAuthRequest.Assertion == nil {
		// Fallback to original behavior
		slog.Warn("No assertion data available for login name, using fallback values", slog.String("loginName", loginName))
		userinfo.SetUserID(loginName)
		userinfo.SetUsername(loginName)
		userinfo.SetEmail(loginName + "@example.com")
		userinfo.SetFullName("Test User")
		userinfo.SetGivenName("Test")
		userinfo.SetSurname("User")

		return nil
	}

	// Process user attributes from the assertion
	s.processUserAttributes(userinfo, foundAuthRequest.Assertion)

	return nil
}

func (s *Storage) Health(_ context.Context) error {
	return nil
}

// Helper methods

// processUserAttributes extracts and sets user attributes from a SAML assertion.
func (s *Storage) processUserAttributes(userinfo models.AttributeSetter, assertion *saml.Assertion) {
	// Set the NameID as UserID
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		userinfo.SetUserID(assertion.Subject.NameID.Value)
		userinfo.SetUsername(assertion.Subject.NameID.Value)
	}

	// Extract attributes from the assertion
	for _, attrStatement := range assertion.AttributeStatements {
		for _, attr := range attrStatement.Attributes {
			switch attr.Name {
			case "username", "Username", "uid", "UID":
				if len(attr.Values) > 0 {
					userinfo.SetUsername(attr.Values[0].Value)
				}
			case "email", "Email", "mail":
				if len(attr.Values) > 0 {
					userinfo.SetEmail(attr.Values[0].Value)
				}
			case "name", "Name", "displayName", "DisplayName":
				if len(attr.Values) > 0 {
					userinfo.SetFullName(attr.Values[0].Value)
				}
			case "givenName", "GivenName", "firstName", "FirstName":
				if len(attr.Values) > 0 {
					userinfo.SetGivenName(attr.Values[0].Value)
				}
			case "surname", "Surname", "lastName", "LastName", "sn":
				if len(attr.Values) > 0 {
					userinfo.SetSurname(attr.Values[0].Value)
				}
			default:
				// For other attributes, we could add custom attribute support here
				slog.Debug("Unhandled attribute",
					slog.String("name", attr.Name),
					slog.Any("values", attr.Values))
			}
		}
	}
}

func (s *Storage) getCertificateAndKey() (*key.CertificateAndKey, error) {
	// Extract the certificate and private key from the tls.Certificate
	if s.cert.PrivateKey == nil {
		return nil, ErrPrivateKeyIsNil
	}

	privateKey, ok := s.cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrPrivateKeyNotRSA
	}

	return &key.CertificateAndKey{
		Certificate: s.cert.Certificate[0],
		Key:         privateKey,
	}, nil
}

// AddAuthRequestForTesting adds an auth request to storage for testing purposes.
func (s *Storage) AddAuthRequestForTesting(authRequest *AuthRequest) {
	s.authRequestsLock.Lock()
	defer s.authRequestsLock.Unlock()
	s.authRequests[authRequest.ID] = authRequest
}

// Logout context management methods

// CreateLogoutContext creates a new logout context for tracking logout flow state.
func (s *Storage) CreateLogoutContext(originType, originID, targetID, relayState string) *LogoutContext {
	id := uuid.New().String()
	logoutContext := &LogoutContext{
		ID:                id,
		OriginType:        originType,
		OriginID:          originID,
		TargetID:          targetID,
		RelayState:        relayState,
		CreatedAt:         time.Now(),
		ProcessedRequests: make(map[string]bool),
	}

	s.logoutContextsLock.Lock()
	s.logoutContexts[id] = logoutContext
	s.logoutContextsLock.Unlock()

	return logoutContext
}

// GetLogoutContext retrieves a logout context by ID.
func (s *Storage) GetLogoutContext(id string) (*LogoutContext, error) {
	s.logoutContextsLock.RLock()
	logoutContext, ok := s.logoutContexts[id]
	s.logoutContextsLock.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrLogoutContextNotFound, id)
	}

	return logoutContext, nil
}

// DeleteLogoutContext removes a logout context from storage.
func (s *Storage) DeleteLogoutContext(id string) {
	s.logoutContextsLock.Lock()
	delete(s.logoutContexts, id)
	s.logoutContextsLock.Unlock()
}

// GetAllowedSPs returns the list of allowed service providers from configuration.
func (s *Storage) GetAllowedSPs() []config.SPConfig {
	return s.config.Proxy.AllowedSP
}

// GetSPCertificateCache returns the SP certificate cache.
func (s *Storage) GetSPCertificateCache() *SPCertificateCache {
	return s.spCertCache
}

// GetConfig returns the configuration.
func (s *Storage) GetConfig() config.Config {
	return s.config
}

// CleanupCompletedAuthRequests removes completed auth requests older than the specified duration.
func (s *Storage) CleanupCompletedAuthRequests(maxAge time.Duration) int {
	s.authRequestsLock.Lock()
	defer s.authRequestsLock.Unlock()

	now := time.Now()
	deleted := 0
	for id, authRequest := range s.authRequests {
		if authRequest.IsDone && !authRequest.CompletedAt.IsZero() && now.Sub(authRequest.CompletedAt) > maxAge {
			delete(s.authRequests, id)
			deleted++
		}
	}

	if deleted > 0 {
		slog.Info("Cleaned up completed auth requests", slog.Int("count", deleted))
	}

	return deleted
}

// CheckAndMarkLogoutRequestProcessed checks if a logout request ID has been processed
// and marks it as processed if not. Returns true if this is a replay.
func (s *Storage) CheckAndMarkLogoutRequestProcessed(contextID, requestID string) (bool, error) {
	if requestID == "" {
		return false, nil // No request ID to check
	}

	s.logoutContextsLock.Lock()
	defer s.logoutContextsLock.Unlock()

	logoutContext, ok := s.logoutContexts[contextID]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrLogoutContextNotFound, contextID)
	}

	// Check if already processed
	if logoutContext.ProcessedRequests[requestID] {
		return true, nil // This is a replay
	}

	// Mark as processed
	logoutContext.ProcessedRequests[requestID] = true

	return false, nil
}

// GetSingleLogoutServiceFromSP extracts SingleLogoutService endpoint from SP metadata.
func (s *Storage) GetSingleLogoutServiceFromSP(ctx context.Context, entityID string) (*SingleLogoutService, error) {
	sp, err := s.GetEntityByID(ctx, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get SP entity: %w", err)
	}

	return extractSingleLogoutService(sp)
}

// extractSingleLogoutService extracts SingleLogoutService endpoint from SP metadata.
func extractSingleLogoutService(sp *serviceprovider.ServiceProvider) (*SingleLogoutService, error) {
	if sp.Metadata == nil || sp.Metadata.SPSSODescriptor == nil {
		return nil, ErrNoSPSSODescriptor
	}

	// Priority order for binding types (as per ADR)
	bindings := []string{
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	}

	for _, binding := range bindings {
		for _, sls := range sp.Metadata.SPSSODescriptor.SingleLogoutService {
			if sls.Binding == binding {
				return &SingleLogoutService{
					Binding:          sls.Binding,
					Location:         sls.Location,
					ResponseLocation: sls.ResponseLocation,
				}, nil
			}
		}
	}

	return nil, ErrNoSingleLogoutService
}
