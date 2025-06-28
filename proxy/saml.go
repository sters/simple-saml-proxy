package proxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"

	"github.com/crewjam/saml"
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

// IDPServiceProvider represents a SAML Service Provider for a specific IDP.
type IDPServiceProvider struct {
	ID          string
	Middleware  *samlsp.Middleware
	MetadataURL *url.URL
}

// SAMLServiceProviders manages multiple SAML Service Providers.
type SAMLServiceProviders struct {
	Providers map[string]*IDPServiceProvider
	Default   *IDPServiceProvider
}

// GetProvider returns the IDP Service Provider for the given ID or the default if not found.
func (s *SAMLServiceProviders) GetProvider(id string) *IDPServiceProvider {
	if id == "" {
		return s.Default
	}

	if provider, ok := s.Providers[id]; ok {
		return provider
	}

	return s.Default
}

// CreateSAMLServiceProviders creates SAML Service Providers for all configured IDPs.
func CreateSAMLServiceProviders(config Config, keyPair tls.Certificate) (*SAMLServiceProviders, error) {
	providers := &SAMLServiceProviders{
		Providers: make(map[string]*IDPServiceProvider),
	}

	for _, idpConfig := range config.IDPs {
		// Create a new SAML Service Provider for this IDP
		key, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("failed to load private key")
		}
		sp, err := samlsp.New(samlsp.Options{
			URL:               *mustParseURL(config.Proxy.EntityID),
			Key:               key,
			Certificate:       keyPair.Leaf,
			IDPMetadata:       &saml.EntityDescriptor{EntityID: idpConfig.EntityID},
			AllowIDPInitiated: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create SAML SP for IDP %s: %w", idpConfig.ID, err)
		}

		// Configure IDP metadata
		idpMetadataURL, err := url.Parse(idpConfig.SSOURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IDP SSO URL for IDP %s: %w", idpConfig.ID, err)
		}

		sp.ServiceProvider.IDPMetadata.IDPSSODescriptors = []saml.IDPSSODescriptor{
			{
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: idpConfig.SSOURL,
					},
				},
			},
		}

		provider := &IDPServiceProvider{
			ID:          idpConfig.ID,
			Middleware:  sp,
			MetadataURL: idpMetadataURL,
		}

		providers.Providers[idpConfig.ID] = provider

		// Set the first IDP as the default
		if providers.Default == nil {
			providers.Default = provider
		}
	}

	return providers, nil
}

// Helper function to parse URLs and panic on error.
func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}

	return u
}
