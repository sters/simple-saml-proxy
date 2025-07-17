package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestValidateEmbeddedSignature(t *testing.T) {
	// Test cases where IDP is nil or certificate retrieval fails
	t.Run("No signature present", func(t *testing.T) {
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           "test-id",
			Version:      "2.0",
			IssueInstant: time.Now(),
			Issuer: &crewjamsaml.Issuer{
				Value: "https://sp.example.com",
			},
		}

		err := validateEmbeddedSignature(logoutRequest, nil, "https://sp.example.com")
		require.NoError(t, err) // No signature, no validation needed
	})

	t.Run("Failed to get logout request element", func(t *testing.T) {
		// Create a LogoutRequest that will return nil from Element()
		// This happens when the request is not properly initialized
		logoutRequest := &crewjamsaml.LogoutRequest{
			Signature: &etree.Element{}, // Empty signature element
			// Missing required fields like ID, Version, etc.
		}

		// Without an IDP, it will log a warning and return nil
		err := validateEmbeddedSignature(logoutRequest, nil, "https://sp.example.com")
		require.NoError(t, err) // Currently returns nil when certificate retrieval fails
	})

	t.Run("IDP not available", func(t *testing.T) {
		// Create a properly signed request
		spCert, spKey := generateTestCertificate(t, "SP Test")
		logoutRequest := createSignedLogoutRequest(t, spKey, spCert)

		// With nil IDP, getSPSigningCertificate will fail but we'll continue
		err := validateEmbeddedSignature(logoutRequest, nil, "https://sp.example.com")
		require.NoError(t, err) // Should log warning but not error
	})
}

func TestValidateEmbeddedSignatureWithValidation(t *testing.T) {
	// This test would require a full IDP setup with proper certificate management
	// For now, we're testing the basic structure and error handling
	t.Run("Signature element parsing", func(t *testing.T) {
		// Create a logout request with signature
		spCert, spKey := generateTestCertificate(t, "SP Test")
		// Create and sign a logout request
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           "test-logout-request-id",
			Version:      "2.0",
			IssueInstant: time.Now().UTC(),
			Destination:  "https://proxy.example.com/saml/slo",
			Issuer: &crewjamsaml.Issuer{
				Value: "https://sp.example.com",
			},
			NameID: &crewjamsaml.NameID{
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				Value:  "user123",
			},
		}

		// Convert to etree element and sign
		doc := etree.NewDocument()
		rootEl := logoutRequest.Element()
		doc.SetRoot(rootEl)

		// Create signing context
		tlsCert := tls.Certificate{
			Certificate: [][]byte{spCert.Raw},
			PrivateKey:  spKey,
		}
		signingContext := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tlsCert))
		signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

		// Sign the element
		signedEl, err := signingContext.SignEnveloped(rootEl)
		require.NoError(t, err)

		// Get the signature element
		signatureEl := signedEl.FindElement("./Signature")
		require.NotNil(t, signatureEl)
		// Set the signature on the logout request
		logoutRequest.Signature = signatureEl

		// Validate that we can get the element back
		el := logoutRequest.Element()
		require.NotNil(t, el)
	})
}

func createSignedLogoutRequest(t *testing.T, privateKey *rsa.PrivateKey, cert *x509.Certificate) *crewjamsaml.LogoutRequest {
	t.Helper()
	// Create a logout request
	logoutRequest := &crewjamsaml.LogoutRequest{
		ID:           "test-logout-request-id",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://proxy.example.com/saml/slo",
		Issuer: &crewjamsaml.Issuer{
			Value: "https://sp.example.com",
		},
		NameID: &crewjamsaml.NameID{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			Value:  "user123",
		},
		SessionIndex: &crewjamsaml.SessionIndex{
			Value: "session-123",
		},
	}

	// Convert to etree element
	doc := etree.NewDocument()
	rootEl := logoutRequest.Element()
	doc.SetRoot(rootEl)

	// Create signing context
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
	}
	signingContext := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tlsCert))
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Sign the element
	signedEl, err := signingContext.SignEnveloped(rootEl)
	require.NoError(t, err)

	// The signature is stored as an etree.Element in the LogoutRequest
	signatureEl := signedEl.FindElement("./Signature")
	require.NotNil(t, signatureEl)
	logoutRequest.Signature = signatureEl

	return logoutRequest
}

func generateTestCertificate(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}
