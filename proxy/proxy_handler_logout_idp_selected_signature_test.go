package proxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignData(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name          string
		data          []byte
		privateKey    interface{}
		sigAlg        string
		expectedError string
	}{
		{
			name:       "Valid SHA256 signature",
			data:       []byte("test data to sign"),
			privateKey: privateKey,
			sigAlg:     sigAlgSHA256,
		},
		{
			name:       "Valid SHA1 signature",
			data:       []byte("test data to sign"),
			privateKey: privateKey,
			sigAlg:     sigAlgSHA1,
		},
		{
			name:          "Unsupported algorithm",
			data:          []byte("test data"),
			privateKey:    privateKey,
			sigAlg:        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
			expectedError: "unsupported signature algorithm",
		},
		{
			name:          "Invalid private key type",
			data:          []byte("test data"),
			privateKey:    "not a key",
			sigAlg:        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			expectedError: "private key must be an RSA key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := signData(tt.data, tt.privateKey, tt.sigAlg)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, signature)

				// Verify the signature
				if rsaKey, ok := tt.privateKey.(*rsa.PrivateKey); ok {
					err = verifySignature(tt.data, signature, &rsaKey.PublicKey, tt.sigAlg)
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestBuildSignedLogoutURL(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	logoutRequest := &crewjamsaml.LogoutRequest{
		ID:      "test_123",
		Version: "2.0",
		Issuer: &crewjamsaml.Issuer{
			Value: "https://proxy.example.com",
		},
	}

	tests := []struct {
		name        string
		destination string
		relayState  string
		sigAlg      string
	}{
		{
			name:        "With relay state",
			destination: "https://idp.example.com/slo",
			relayState:  "test_relay_state",
			sigAlg:      sigAlgSHA256,
		},
		{
			name:        "Without relay state",
			destination: "https://idp.example.com/slo",
			relayState:  "",
			sigAlg:      sigAlgSHA256,
		},
		{
			name:        "Default signature algorithm",
			destination: "https://idp.example.com/slo",
			relayState:  "test",
			sigAlg:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedURL, err := buildSignedLogoutURL(
				logoutRequest,
				tt.destination,
				tt.relayState,
				privateKey,
				tt.sigAlg,
			)
			require.NoError(t, err)

			// Parse the URL and verify components
			parsedURL, err := url.Parse(signedURL)
			require.NoError(t, err)

			query := parsedURL.Query()

			// Verify required parameters are present
			assert.NotEmpty(t, query.Get("SAMLRequest"))
			assert.NotEmpty(t, query.Get("SigAlg"))
			assert.NotEmpty(t, query.Get("Signature"))

			// Verify relay state
			if tt.relayState != "" {
				assert.Equal(t, tt.relayState, query.Get("RelayState"))
			} else {
				assert.Empty(t, query.Get("RelayState"))
			}

			// Verify signature algorithm
			expectedSigAlg := tt.sigAlg
			if expectedSigAlg == "" {
				expectedSigAlg = sigAlgSHA256
			}
			assert.Equal(t, expectedSigAlg, query.Get("SigAlg"))

			// Verify the signature can be decoded
			signature, err := base64.StdEncoding.DecodeString(query.Get("Signature"))
			require.NoError(t, err)
			assert.NotEmpty(t, signature)
		})
	}
}

// Helper function to verify signature (for testing).
func verifySignature(data []byte, signature []byte, publicKey *rsa.PublicKey, sigAlg string) error {
	var hashFunc crypto.Hash
	switch sigAlg {
	case sigAlgSHA1:
		hashFunc = crypto.SHA1
	case sigAlgSHA256:
		hashFunc = crypto.SHA256
	default:
		hashFunc = crypto.SHA256
	}

	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(publicKey, hashFunc, digest, signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
