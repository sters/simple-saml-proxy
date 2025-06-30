package proxy

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/zitadel/saml/pkg/provider"
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
	EntityID   string
	idp        *provider.Provider
	idpStorage *ProxyStorage
}

// ServiceProvider represents a SAML Service Provider for a specific IDP.
type ServiceProvider struct {
	ID         string
	Middleware *samlsp.Middleware
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
		EntityID:   config.Proxy.EntityID,
		idp:        p,
		idpStorage: storage,
	}, nil
}

// CreateServiceProviders creates Service Providers for all configured IDP.
func CreateServiceProviders(ctx context.Context, config Config) (*ServiceProviders, error) {
	providers := &ServiceProviders{
		Providers: make(map[string]*ServiceProvider),
	}

	keyPair, err := LoadCertificate(config.Proxy.CertificatePath, config.Proxy.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	for _, idpConfig := range config.IDP {
		rootURL, err := url.Parse(config.Proxy.EntityID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IDP URL for IDP %s: %w", idpConfig.ID, err)
		}

		var ed *saml.EntityDescriptor

		// read metadata if specified
		if idpConfig.MetadataURL != "" {
			idpMetadataURL, err := url.Parse(idpConfig.MetadataURL)
			if err != nil {
				slog.Warn("Invalid IDP metadata URL", slog.String("url", idpConfig.MetadataURL))
			} else {
				ed, err = samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
				if err != nil {
					slog.Warn("Failed to fetch IDP metadata", slog.String("url", idpConfig.MetadataURL))
				}
			}
		}

		if ed == nil {
			idpCertPEM, err := os.ReadFile(idpConfig.CertificatePath)
			if err != nil {
				return nil, fmt.Errorf("failed to read IDP certificate for IDP %s: %w", idpConfig.ID, err)
			}

			idpCertBlock, _ := pem.Decode(idpCertPEM)
			if idpCertBlock == nil {
				return nil, fmt.Errorf("failed to decode PEM block containing certificate for IDP %s", idpConfig.ID)
			}

			base64cert := base64.StdEncoding.EncodeToString(idpCertBlock.Bytes)

			ed = &saml.EntityDescriptor{
				EntityID: idpConfig.EntityID,
				IDPSSODescriptors: []saml.IDPSSODescriptor{
					{
						SSODescriptor: saml.SSODescriptor{
							RoleDescriptor: saml.RoleDescriptor{
								KeyDescriptors: []saml.KeyDescriptor{
									{
										Use: "signing",
										KeyInfo: saml.KeyInfo{
											X509Data: saml.X509Data{
												X509Certificates: []saml.X509Certificate{
													{
														Data: base64cert,
													},
												},
											},
										},
									},
								},
							},
						},
						SingleSignOnServices: []saml.Endpoint{
							{
								Binding:  saml.HTTPRedirectBinding,
								Location: idpConfig.SSOURL,
							},
						},
					},
				},
			}
		}

		slog.Info("Creating SAML SP for IDP", slog.Any("EntityDescriptor", ed))

		sp, err := samlsp.New(samlsp.Options{
			URL:               *rootURL,
			Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:       keyPair.Leaf,
			IDPMetadata:       ed,
			AllowIDPInitiated: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create SAML SP for IDP %s: %w", idpConfig.ID, err)
		}

		provider := &ServiceProvider{
			ID:         idpConfig.ID,
			Middleware: sp,
		}

		providers.Providers[idpConfig.ID] = provider

		// Set the first IDP as the default
		if providers.Default == nil {
			providers.Default = provider
		}
	}

	return providers, nil
}
