package proxy

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

const (
	sigAlgSHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sigAlgSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

var (
	errUnsupportedSigAlg = errors.New("unsupported signature algorithm")
	errPrivateKeyNotRSA  = errors.New("private key must be an RSA key")
)

// handleLogoutIDPSelected handles the IdP selection for logout and creates the upstream logout request.
func handleLogoutIDPSelected(idp *saml.IDP, providers *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get logout context ID from cookie
		logoutCtxCookie, err := r.Cookie("logout_context_id")
		if err != nil {
			slog.Error("Failed to get logout context cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		// Get logout context from storage
		storage := idp.GetStorage()
		logoutCtx, err := storage.GetLogoutContext(logoutCtxCookie.Value)
		if err != nil {
			slog.Error("Failed to get logout context",
				slog.String("id", logoutCtxCookie.Value),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		// Get selected IdP
		idpID := r.FormValue("idpID")
		if idpID == "" {
			slog.Error("No IdP ID provided")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		provider, ok := providers.Providers[idpID]
		if !ok {
			slog.Error("Invalid IdP ID", slog.String("idp", idpID))
			http.Error(w, "Invalid IdP ID", http.StatusBadRequest)

			return
		}

		// Update logout context with target IdP
		logoutCtx.TargetID = idpID

		slog.Info("IdP selected for logout",
			slog.String("idp", idpID),
			slog.String("originSP", logoutCtx.OriginID),
		)

		// Create logout request to upstream IdP
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           fmt.Sprintf("id-%x", randomBytes(20)),
			IssueInstant: time.Now(),
			Version:      "2.0",
			Issuer: &crewjamsaml.Issuer{
				Value: idp.IDP.GetEntityID(r.Context()),
			},
			NameID: &crewjamsaml.NameID{
				// This would normally come from the original logout request or session
				// For now, using a placeholder
				Value:  "user@example.com",
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
			},
		}

		// Check if the provider's SP has a SingleLogoutService URL
		if provider.Middleware.ServiceProvider.IDPMetadata == nil ||
			len(provider.Middleware.ServiceProvider.IDPMetadata.IDPSSODescriptors) == 0 ||
			len(provider.Middleware.ServiceProvider.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices) == 0 {
			slog.Error("IdP does not support Single Logout")
			http.Error(w, "Selected IdP does not support Single Logout", http.StatusBadRequest)

			return
		}

		sloService := provider.Middleware.ServiceProvider.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices[0]
		logoutRequest.Destination = sloService.Location

		// Build the logout URL
		// TODO: Pass proxy's private key and certificate for signing when available
		logoutURL, err := buildLogoutURL(logoutRequest, sloService.Location, logoutCtx.ID)
		if err != nil {
			slog.Error("Failed to build logout URL", slog.String("error", err.Error()))
			http.Error(w, "Failed to create logout request", http.StatusInternalServerError)

			return
		}

		// Store IdP ID in cookie for response handling
		http.SetCookie(w, &http.Cookie{
			Name:     "logout_idp_id",
			Value:    idpID,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecureCookie(r),
			MaxAge:   300, // 5 minutes
		})

		// Redirect to upstream IdP
		slog.Info("Redirecting to upstream IdP for logout", slog.String("url", logoutURL))
		http.Redirect(w, r, logoutURL, http.StatusFound)
	}
}

// TODO: Add signature support when proxy private key is available.
func buildLogoutURL(logoutRequest *crewjamsaml.LogoutRequest, destination string, relayState string) (string, error) {
	// Marshal the logout request
	doc := etree.NewDocument()
	doc.SetRoot(logoutRequest.Element())
	xmlBytes, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("failed to marshal logout request: %w", err)
	}

	// Compress using deflate
	compressed, err := deflateCompress([]byte(xmlBytes))
	if err != nil {
		return "", fmt.Errorf("failed to compress logout request: %w", err)
	}

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(compressed)

	// Build URL
	logoutURL, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("failed to parse destination URL: %w", err)
	}

	query := logoutURL.Query()
	query.Set("SAMLRequest", encoded)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}

	// TODO: Add signature when configuration requires it
	// This would involve:
	// 1. Add SigAlg parameter (e.g., http://www.w3.org/2001/04/xmldsig-more#rsa-sha256)
	// 2. Create signature data string according to SAML spec
	// 3. Sign the data using proxy's private key
	// 4. Base64 encode the signature and add as Signature parameter

	logoutURL.RawQuery = query.Encode()

	return logoutURL.String(), nil
}

// buildSignedLogoutURL creates a signed logout URL for HTTP-Redirect binding.
func buildSignedLogoutURL(logoutRequest *crewjamsaml.LogoutRequest, destination string, relayState string, privateKey interface{}, sigAlg string) (string, error) {
	// First build the unsigned URL
	unsignedURL, err := buildLogoutURL(logoutRequest, destination, relayState)
	if err != nil {
		return "", err
	}

	// Parse the URL to modify query parameters
	logoutURL, err := url.Parse(unsignedURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse logout URL: %w", err)
	}

	// Get the current query values
	query := logoutURL.Query()

	// Add signature algorithm
	if sigAlg == "" {
		sigAlg = sigAlgSHA256
	}
	query.Set("SigAlg", sigAlg)

	// Create the signature data string according to SAML spec
	// The order matters: SAMLRequest, RelayState (if present), SigAlg
	var signatureData string
	samlRequest := query.Get("SAMLRequest")
	if relayState != "" {
		signatureData = fmt.Sprintf("SAMLRequest=%s&RelayState=%s&SigAlg=%s",
			url.QueryEscape(samlRequest),
			url.QueryEscape(relayState),
			url.QueryEscape(sigAlg))
	} else {
		signatureData = fmt.Sprintf("SAMLRequest=%s&SigAlg=%s",
			url.QueryEscape(samlRequest),
			url.QueryEscape(sigAlg))
	}

	// Sign the data
	signature, err := signData([]byte(signatureData), privateKey, sigAlg)
	if err != nil {
		return "", fmt.Errorf("failed to sign logout request: %w", err)
	}

	// Base64 encode the signature and add to query
	query.Set("Signature", base64.StdEncoding.EncodeToString(signature))

	// Update the URL with the new query including signature
	logoutURL.RawQuery = query.Encode()

	return logoutURL.String(), nil
}

// signData signs the given data using the private key and specified algorithm.
func signData(data []byte, privateKey interface{}, sigAlg string) ([]byte, error) {
	// Determine hash algorithm
	var hashFunc crypto.Hash
	switch sigAlg {
	case sigAlgSHA1:
		hashFunc = crypto.SHA1
	case sigAlgSHA256:
		hashFunc = crypto.SHA256
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedSigAlg, sigAlg)
	}

	// Compute hash
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Sign with private key
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errPrivateKeyNotRSA
	}

	signature, err := rsa.SignPKCS1v15(nil, rsaKey, hashFunc, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}
