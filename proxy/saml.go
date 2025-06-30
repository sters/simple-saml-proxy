package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/zitadel/saml/pkg/provider"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
)

// LoadCertificate loads and parses the SP certificate and private key.
func LoadCertificate(certPath, keyPath string) (tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	return keyPair, nil
}

// IDP represents the SAML Identity Provider configuration.
type IDP struct {
	// Using zitadel/saml
	EntityID string
	idp      *provider.Provider
}

// ServiceProvider represents a SAML Service Provider for a specific IDP.
type ServiceProvider struct {
	ID string
	sp *serviceprovider.ServiceProvider
}

// ServiceProviders manages multiple SAML Service Providers.
type ServiceProviders struct {
	Providers map[string]*ServiceProvider
	Default   *ServiceProvider
}

// GetProvider returns the IDP Service Provider for the given ID or the default if not found.
func (s *ServiceProviders) GetProvider(id string) *ServiceProvider {
	if id == "" {
		return s.Default
	}

	if provider, ok := s.Providers[id]; ok {
		return provider
	}

	return s.Default
}

// CreateProxyIDP creates a SAML Identity Provider middleware from the configuration.
func CreateProxyIDP(config Config) (*IDP, error) {
	// Create a new storage
	storage, err := NewProxyStorage(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	slog.Info(
		"Creating SAML IDP with zitadel/saml",
		slog.String("entityID", config.Proxy.EntityID),
	)

	// Create metadata endpoint
	metadataEndpoint := provider.NewEndpoint(provider.DefaultMetadataEndpoint)

	// Create endpoints
	ssoEndpoint := provider.NewEndpoint("/sso")
	sloEndpoint := provider.NewEndpoint("/slo")

	// Create IDP config
	idpConfig := &provider.IdentityProviderConfig{
		MetadataIDPConfig: &provider.MetadataIDPConfig{
			ValidUntil:    24 * time.Hour, // Metadata valid for 24 hours
			CacheDuration: "PT24H",        // Cache for 24 hours
		},
		Endpoints: &provider.EndpointConfig{
			SingleSignOn: &ssoEndpoint,
			SingleLogOut: &sloEndpoint,
		},
	}

	// Create provider config
	providerConfig := &provider.Config{
		Metadata:  &metadataEndpoint,
		IDPConfig: idpConfig,
		Organisation: &provider.Organisation{
			Name:        "SAML Proxy",
			DisplayName: "SAML Proxy",
			URL:         config.Proxy.EntityID,
		},
	}

	// Create issuer function
	issuerFunc := func(insecure bool) (provider.IssuerFromRequest, error) {
		return func(r *http.Request) string {
			r.FormValue("SAMLRequest")
			return config.Proxy.EntityID
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
		EntityID: config.Proxy.EntityID,
		idp:      p,
	}, nil
}

// CreateServiceProviders creates Service Providers for all configured IDP.
func CreateServiceProviders(ctx context.Context, config Config) (*ServiceProviders, error) {
	providers := &ServiceProviders{
		Providers: make(map[string]*ServiceProvider),
	}

	// Load certificate
	_, err := LoadCertificate(config.Proxy.CertificatePath, config.Proxy.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	for _, idpConfig := range config.IDP {
		slog.Info(
			"Creating SP for IDP with zitadel/saml",
			slog.String("idp", idpConfig.ID),
			slog.String("entityID", idpConfig.EntityID),
			slog.String("ssoURL", idpConfig.SSOURL),
		)

		// Create a simple metadata XML for the SP
		metadata := fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
			<SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
				<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/saml/acs" index="0" isDefault="true"/>
			</SPSSODescriptor>
		</EntityDescriptor>`, config.Proxy.EntityID, config.Proxy.EntityID)

		// Create a service provider config
		spConfig := &serviceprovider.Config{
			Metadata: []byte(metadata),
		}

		// Create a login URL function
		loginURL := func(id string) string {
			return ""
		}

		// Create a service provider
		sp, err := serviceprovider.NewServiceProvider(idpConfig.ID, spConfig, loginURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create service provider: %w", err)
		}

		// Create a service provider
		provider := &ServiceProvider{
			ID: idpConfig.ID,
			sp: sp,
		}

		providers.Providers[idpConfig.ID] = provider

		// Set the first IDP as the default
		if providers.Default == nil {
			providers.Default = provider
		}
	}

	return providers, nil
}
