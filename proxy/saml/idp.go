package saml

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/zitadel/saml/pkg/provider"
)

// IDP represents the SAML Identity Provider configuration.
type IDP struct {
	// Using zitadel/saml
	EntityID   string
	IDP        *provider.Provider // Exported for proxy package access
	IDPStorage *Storage           // Exported for proxy package access
}

// GetStorage returns the IDP's storage for testing purposes.
func (i *IDP) GetStorage() *Storage {
	return i.IDPStorage
}

// GetProvider returns the zitadel/saml provider.
func (i *IDP) GetProvider() *provider.Provider {
	return i.IDP
}

// CreateProxyIDP creates a SAML Identity Provider middleware from the configuration.
func CreateProxyIDP(cfg config.Config) (*IDP, error) {
	// Create a new storage
	storage, err := NewStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	slog.Info(
		"Creating SAML IDP with zitadel/saml",
		slog.String("entityID", cfg.Proxy.EntityID),
	)

	// Create metadata endpoint
	metadataEndpoint := provider.NewEndpoint(provider.DefaultMetadataEndpoint)

	// Create endpoints
	ssoEndpoint := provider.NewEndpoint("/sso")
	callbackEndpoint := provider.NewEndpoint("/callback")

	// Create IDP config
	idpConfig := &provider.IdentityProviderConfig{
		MetadataIDPConfig: &provider.MetadataIDPConfig{
			ValidUntil:    24 * time.Hour, // Metadata valid for 24 hours
			CacheDuration: "PT24H",        // Cache for 24 hours
		},
		Endpoints: &provider.EndpointConfig{
			SingleSignOn: &ssoEndpoint,
			Callback:     &callbackEndpoint,
		},
		SignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	// Create provider config
	providerConfig := &provider.Config{
		Metadata:  &metadataEndpoint,
		IDPConfig: idpConfig,
		Organisation: &provider.Organisation{
			Name:        "SAML Proxy",
			DisplayName: "SAML Proxy",
			URL:         cfg.Proxy.EntityID,
		},
	}

	// Create issuer function
	issuerFunc := func(_ bool) (provider.IssuerFromRequest, error) {
		return func(r *http.Request) string {
			r.FormValue("SAMLRequest")

			return cfg.Proxy.EntityID
		}, nil
	}

	// Create provider
	p, err := provider.NewProvider(
		storage,
		issuerFunc,
		providerConfig,
		provider.WithAllowInsecure(), // Allow HTTP for development
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	return &IDP{
		EntityID:   cfg.Proxy.EntityID,
		IDP:        p,
		IDPStorage: storage,
	}, nil
}
