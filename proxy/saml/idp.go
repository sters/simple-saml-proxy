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
	EntityID   string
	IDP        *provider.Provider
	IDPStorage *Storage
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
	storage, err := NewStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	slog.Info(
		"Creating SAML IDP with zitadel/saml",
		slog.String("entityID", cfg.Proxy.EntityID),
	)

	metadataEndpoint := provider.NewEndpoint("/idp/metadata")
	ssoEndpoint := provider.NewEndpoint("/idp/sso")
	callbackEndpoint := provider.NewEndpoint("/idp/acs")

	idpConfig := &provider.IdentityProviderConfig{
		MetadataIDPConfig: &provider.MetadataIDPConfig{
			ValidUntil:    24 * time.Hour,
			CacheDuration: "PT24H",
		},
		Endpoints: &provider.EndpointConfig{
			SingleSignOn: &ssoEndpoint,
			Callback:     &callbackEndpoint,
		},
		SignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	providerConfig := &provider.Config{
		Metadata:  &metadataEndpoint,
		IDPConfig: idpConfig,
		Organisation: &provider.Organisation{
			Name:        "SAML Proxy",
			DisplayName: "SAML Proxy",
			URL:         cfg.Proxy.EntityID + "/idp/metadata",
		},
	}

	issuerFunc := func(_ bool) (provider.IssuerFromRequest, error) {
		return func(_ *http.Request) string {
			return cfg.Proxy.EntityID
		}, nil
	}

	p, err := provider.NewProvider(
		storage,
		issuerFunc,
		providerConfig,
		provider.WithAllowInsecure(),
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
