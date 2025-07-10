package saml

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/sters/simple-saml-proxy/config"
)

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

// CreateServiceProviders creates Service Providers for all configured IDP.
func CreateServiceProviders(ctx context.Context, cfg config.Config) (*ServiceProviders, error) {
	providers := &ServiceProviders{
		Providers: make(map[string]*ServiceProvider),
	}

	keyPair, err := LoadCertificate(cfg.Proxy.CertificatePath, cfg.Proxy.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	for _, idpConfig := range cfg.IDP {
		rootURL, err := url.Parse(cfg.Proxy.EntityID)
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
				ed, err = samlsp.FetchMetadata(ctx, http.DefaultClient, *idpMetadataURL)
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
				return nil, fmt.Errorf("%w for IDP %s", ErrDecodePEMBlock, idpConfig.ID)
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

		privateKey, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w for IDP %s", ErrPrivateKeyNotRSAKey, idpConfig.ID)
		}

		sp, err := samlsp.New(samlsp.Options{
			URL:               *rootURL,
			Key:               privateKey,
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
