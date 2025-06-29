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
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/crewjam/saml/samlsp"
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
	Server *samlidp.Server
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
	keyPair, err := LoadCertificate(config.Proxy.CertificatePath, config.Proxy.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	idpURL, err := url.Parse(config.Proxy.EntityID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IDP Entity ID URL: %w", err)
	}

	idp, err := samlidp.New(samlidp.Options{
		URL:         *idpURL,
		Key:         keyPair.PrivateKey,
		Certificate: keyPair.Leaf,
		Store:       &samlidp.MemoryStore{}, // TODO: これは何か外部化しないといけないかも
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML IDP middleware: %w", err)
	}

	return &IDP{
		Server: idp,
	}, nil
}

// CreateServiceProviders creates IDP Service Providers for all configured IDP.
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

		// TODO: むずすぎる。metadataが読めるならmetadataを読みたい

		idpCertPEM, err := os.ReadFile(idpConfig.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read IDP certificate for IDP %s: %w", idpConfig.ID, err)
		}

		idpCertBlock, _ := pem.Decode(idpCertPEM)
		if idpCertBlock == nil {
			return nil, fmt.Errorf("failed to decode PEM block containing certificate for IDP %s", idpConfig.ID)
		}

		base64cert := base64.StdEncoding.EncodeToString(idpCertBlock.Bytes)

		slog.Info(
			"IDP certificate",
			slog.String("idp", idpConfig.ID),
			slog.String("cert", base64cert),
		)

		sp, err := samlsp.New(samlsp.Options{
			URL:         *rootURL,
			Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate: keyPair.Leaf,
			IDPMetadata: &saml.EntityDescriptor{
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
			},
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
