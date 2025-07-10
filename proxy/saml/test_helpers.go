package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// GenerateTestCertificate generates a self-signed certificate and private key for testing.
func GenerateTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	var certPath, keyPath string
	tempDir := t.TempDir()

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Write the certificate to a file
	certPath = filepath.Join(tempDir, "cert.pem")
	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(t, err)

	// Write the private key to a file
	keyPath = filepath.Join(tempDir, "key.pem")
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	require.NoError(t, err)

	return certPath, keyPath
}
