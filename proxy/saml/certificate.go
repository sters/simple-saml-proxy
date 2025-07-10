package saml

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrDecodePEMBlock      = errors.New("failed to decode PEM block containing certificate")
	ErrPrivateKeyNotRSAKey = errors.New("private key is not an RSA key")
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
