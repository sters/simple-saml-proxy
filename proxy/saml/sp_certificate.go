package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
)

var (
	// ErrNoSigningCertificate indicates no signing certificate was found in metadata.
	ErrNoSigningCertificate = errors.New("no signing certificate found in metadata")
	// ErrInvalidCertificate indicates the certificate data is malformed.
	ErrInvalidCertificate = errors.New("invalid certificate data")
)

// SPCertificateCache caches SP signing certificates to avoid repeated metadata fetches.
type SPCertificateCache struct {
	certificates map[string]*x509.Certificate
	mu           sync.RWMutex
}

// NewSPCertificateCache creates a new certificate cache.
func NewSPCertificateCache() *SPCertificateCache {
	return &SPCertificateCache{
		certificates: make(map[string]*x509.Certificate),
	}
}

// Get retrieves a certificate from the cache.
func (c *SPCertificateCache) Get(entityID string) (*x509.Certificate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cert, ok := c.certificates[entityID]

	return cert, ok
}

// Set stores a certificate in the cache.
func (c *SPCertificateCache) Set(entityID string, cert *x509.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certificates[entityID] = cert
}

// GetSPSigningCertificateFromMetadata retrieves the signing certificate from SP metadata.
func GetSPSigningCertificateFromMetadata(ctx context.Context, cfg config.Config, spEntityID string, cache *SPCertificateCache) (*x509.Certificate, error) {
	// Check cache first
	if cache != nil {
		if cert, ok := cache.Get(spEntityID); ok {
			return cert, nil
		}
	}

	// Find the SP configuration
	var spConfig *config.SPConfig
	for i := range cfg.Proxy.AllowedSP {
		if cfg.Proxy.AllowedSP[i].EntityID == spEntityID {
			spConfig = &cfg.Proxy.AllowedSP[i]

			break
		}
	}

	if spConfig == nil {
		return nil, fmt.Errorf("SP not found in allowed list: %s", spEntityID)
	}

	// If no metadata URL is configured, we can't fetch the certificate
	if spConfig.MetadataURL == "" {
		return nil, fmt.Errorf("no metadata URL configured for SP: %s", spEntityID)
	}

	// Fetch and parse the metadata
	metadataBytes, err := ReadMetadataFromURLWithRetry(ctx, http.DefaultClient, spConfig.MetadataURL, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SP metadata: %w", err)
	}

	// Parse the metadata to extract the certificate
	cert, err := extractSigningCertificateFromMetadata(metadataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract certificate from metadata: %w", err)
	}

	// Cache the certificate
	if cache != nil {
		cache.Set(spEntityID, cert)
	}

	slog.Info("Successfully retrieved SP signing certificate",
		slog.String("sp", spEntityID),
		slog.String("subject", cert.Subject.String()))

	return cert, nil
}

// extractSigningCertificateFromMetadata parses SAML metadata and extracts the signing certificate.
func extractSigningCertificateFromMetadata(metadataBytes []byte) (*x509.Certificate, error) {
	// Parse the metadata using crewjam/saml
	metadata := &saml.EntityDescriptor{}
	if err := xml.Unmarshal(metadataBytes, metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Look for signing certificates in SPSSODescriptor
	for _, spDesc := range metadata.SPSSODescriptors {
		for _, keyDesc := range spDesc.KeyDescriptors {
			// Skip if not for signing (empty use means it can be used for both signing and encryption)
			if keyDesc.Use != "" && keyDesc.Use != "signing" {
				continue
			}

			// Extract the certificate
			cert, err := extractCertificateFromKeyDescriptor(keyDesc)
			if err == nil {
				return cert, nil
			}
			// Log but continue looking for other certificates
			slog.Warn("Failed to extract certificate from KeyDescriptor",
				slog.String("error", err.Error()))
		}
	}

	return nil, ErrNoSigningCertificate
}

// extractCertificateFromKeyDescriptor extracts an X.509 certificate from a KeyDescriptor.
func extractCertificateFromKeyDescriptor(keyDesc saml.KeyDescriptor) (*x509.Certificate, error) {
	for _, x509Cert := range keyDesc.KeyInfo.X509Data.X509Certificates {
		if x509Cert.Data == "" {
			continue
		}

		// First try as PEM encoded
		block, _ := pem.Decode([]byte(x509Cert.Data))
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return cert, nil
			}
		}

		// Clean the base64 data (remove any whitespace/newlines)
		cleanData := strings.ReplaceAll(x509Cert.Data, "\n", "")
		cleanData = strings.ReplaceAll(cleanData, "\r", "")
		cleanData = strings.ReplaceAll(cleanData, " ", "")
		cleanData = strings.ReplaceAll(cleanData, "\t", "")

		// Try to decode as base64
		certData, err := base64.StdEncoding.DecodeString(cleanData)
		if err != nil {
			// Log warning but continue to next certificate
			slog.Warn("Failed to decode certificate data",
				slog.String("error", err.Error()))

			continue
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		return cert, nil
	}

	return nil, ErrInvalidCertificate
}
