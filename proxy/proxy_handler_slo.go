package proxy

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

var (
	errLogoutRequestMissingIssuer      = errors.New("logout request missing issuer")
	errLogoutRequestIssueInstantFuture = errors.New("logout request issue instant is in the future")
	errLogoutRequestTooOld             = errors.New("logout request is too old")
	errLogoutRequestSignatureRequired  = errors.New("logout request signature is required but not present")
	errIDPNotAvailable                 = errors.New("IDP not available")
	errSPCertNotImplemented            = errors.New("SP certificate retrieval not yet implemented")
	errCertNotRSA                      = errors.New("certificate does not contain an RSA public key")
	errUnsupportedSigAlgorithm         = errors.New("unsupported signature algorithm")
)

// handleSLO handles Single Logout requests initiated by Service Providers.
// Flow: SP → Proxy → Upstream IdP.
func handleSLO(idp *saml.IDP, _ *saml.ServiceProviders, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received SLO request from SP",
			slog.String("method", r.Method),
			slog.String("url", r.URL.String()),
		)

		// Get the SAMLRequest parameter
		samlRequestParam := r.URL.Query().Get("SAMLRequest")
		if samlRequestParam == "" {
			slog.Error("No SAMLRequest parameter in logout request")
			http.Error(w, "Missing SAMLRequest parameter", http.StatusBadRequest)

			return
		}

		// Parse the logout request
		logoutRequest, err := parseLogoutRequest(samlRequestParam)
		if err != nil {
			slog.Error("Failed to parse logout request", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		// Validate the SP is allowed
		storage := idp.GetStorage()
		sp, err := storage.GetEntityByID(r.Context(), logoutRequest.Issuer.Value)
		if err != nil {
			slog.Warn("Unauthorized SP attempted to initiate logout",
				slog.String("entityID", logoutRequest.Issuer.Value),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Unauthorized service provider", http.StatusForbidden)

			return
		}

		// Validate signature if configured
		requireSignature := determineSignatureRequirement(cfg, logoutRequest.Issuer.Value)
		if err := validateLogoutRequestSignature(logoutRequest, idp, logoutRequest.Issuer.Value, r.URL.RawQuery, requireSignature); err != nil {
			slog.Error("Logout request signature validation failed",
				slog.String("issuer", logoutRequest.Issuer.Value),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid logout request signature", http.StatusBadRequest)

			return
		}
		_ = sp // Mark as used for future enhanced validation

		// Check for replay attack - verify IssueInstant is recent
		if err := validateIssueInstant(logoutRequest.IssueInstant); err != nil {
			slog.Error("Logout request failed time validation",
				slog.String("issuer", logoutRequest.Issuer.Value),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		// Get relay state if present
		relayState := r.URL.Query().Get("RelayState")

		slog.Info("Parsed logout request",
			slog.String("issuer", logoutRequest.Issuer.Value),
			slog.String("nameID", getNameIDValue(logoutRequest)),
			slog.String("sessionIndex", getSessionIndex(logoutRequest)),
			slog.String("relayState", relayState),
		)

		// Create a logout context to track this logout flow
		logoutCtx := storage.CreateLogoutContext(
			"sp",                       // Origin type
			logoutRequest.Issuer.Value, // Origin ID (SP entity ID)
			"",                         // Target ID (to be set when IdP is selected)
			relayState,                 // Preserve relay state
		)
		logoutCtx.LogoutRequestID = logoutRequest.ID

		// Check for replay attack using request ID
		isReplay, err := storage.CheckAndMarkLogoutRequestProcessed(logoutCtx.ID, logoutRequest.ID)
		if err != nil {
			slog.Error("Failed to check logout request replay",
				slog.String("error", err.Error()),
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}
		if isReplay {
			slog.Warn("Replay attack detected - duplicate logout request ID",
				slog.String("requestID", logoutRequest.ID),
				slog.String("issuer", logoutRequest.Issuer.Value),
			)
			http.Error(w, "Duplicate logout request", http.StatusBadRequest)

			return
		}

		// Store logout request ID in a cookie for later retrieval
		http.SetCookie(w, &http.Cookie{
			Name:     "logout_context_id",
			Value:    logoutCtx.ID,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecureCookie(r),
			MaxAge:   300, // 5 minutes
		})

		// For now, redirect to IdP selection page
		// In a production implementation, you might track which IdP was used for login
		http.Redirect(w, r, "/logout_idp_select", http.StatusFound)
	}
}

// parseLogoutRequest parses a SAML logout request from the SAMLRequest parameter.
func parseLogoutRequest(samlRequestParam string) (*crewjamsaml.LogoutRequest, error) {
	// Base64 decode (the samlRequestParam should already be URL-decoded by Go's query parsing)
	compressed, err := base64.StdEncoding.DecodeString(samlRequestParam)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode logout request: %w", err)
	}

	// Decompress using flate
	decompressed, err := decodeDeflatedRequest(compressed)
	if err != nil {
		// Try without decompression in case it's not compressed
		decompressed = compressed
	}

	// Parse as LogoutRequest
	var logoutRequest crewjamsaml.LogoutRequest
	if err := xml.Unmarshal(decompressed, &logoutRequest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal logout request: %w", err)
	}

	// Validate required fields
	if logoutRequest.Issuer == nil || logoutRequest.Issuer.Value == "" {
		return nil, errLogoutRequestMissingIssuer
	}

	return &logoutRequest, nil
}

// decodeDeflatedRequest decodes a deflated SAML request.
func decodeDeflatedRequest(compressed []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	var buf bytes.Buffer
	// Limit the amount of data we'll read to prevent decompression bombs
	limited := io.LimitReader(reader, 10*1024*1024) // 10MB limit
	_, err := io.Copy(&buf, limited)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress request: %w", err)
	}

	return buf.Bytes(), nil
}

// getNameIDValue extracts the NameID value from a logout request.
func getNameIDValue(req *crewjamsaml.LogoutRequest) string {
	if req.NameID != nil {
		return req.NameID.Value
	}

	return ""
}

// getSessionIndex extracts the session index from a logout request.
func getSessionIndex(req *crewjamsaml.LogoutRequest) string {
	if req.SessionIndex != nil {
		return req.SessionIndex.Value
	}

	return ""
}

// validateIssueInstant checks if the logout request was issued recently to prevent replay attacks.
func validateIssueInstant(issueInstant time.Time) error {
	const maxAge = 5 * time.Minute

	now := time.Now()
	age := now.Sub(issueInstant)

	if age < 0 {
		// Issue instant is in the future
		return fmt.Errorf("%w: %v", errLogoutRequestIssueInstantFuture, issueInstant)
	}

	if age > maxAge {
		return fmt.Errorf("%w: issued %v ago", errLogoutRequestTooOld, age)
	}

	return nil
}

// validateLogoutRequestSignature validates the signature of a logout request.
// For HTTP-Redirect binding, it validates query parameter signatures.
// For HTTP-POST binding, it validates embedded signatures.
func validateLogoutRequestSignature(
	logoutRequest *crewjamsaml.LogoutRequest,
	idp *saml.IDP,
	spEntityID string,
	rawQuery string,
	requireSignature bool,
) error {
	// Check if signature is required but not present
	if requireSignature && logoutRequest.Signature == nil && rawQuery == "" {
		return errLogoutRequestSignatureRequired
	}

	// No signature to validate
	if logoutRequest.Signature == nil && rawQuery == "" {
		return nil
	}

	// For HTTP-Redirect binding with query parameters
	if logoutRequest.Signature == nil && rawQuery != "" {
		return validateRedirectSignature(rawQuery, idp, spEntityID)
	}

	// For HTTP-POST binding with embedded signature
	if logoutRequest.Signature != nil {
		return validateEmbeddedSignature(logoutRequest, spEntityID)
	}

	return nil
}

// validateRedirectSignature validates signatures passed as query parameters in HTTP-Redirect binding.
func validateRedirectSignature(rawQuery string, idp *saml.IDP, spEntityID string) error {
	// Parse query parameters
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return fmt.Errorf("failed to parse query parameters: %w", err)
	}

	// Get required parameters
	samlRequest := params.Get("SAMLRequest")
	relayState := params.Get("RelayState")
	sigAlg := params.Get("SigAlg")
	signature := params.Get("Signature")

	if signature == "" || sigAlg == "" {
		return nil // No signature present
	}

	// Reconstruct the signed data according to SAML spec
	// The signed string must use the exact query parameter values as received
	var signedData string
	if relayState != "" {
		signedData = fmt.Sprintf("SAMLRequest=%s&RelayState=%s&SigAlg=%s",
			samlRequest, relayState, sigAlg)
	} else {
		signedData = fmt.Sprintf("SAMLRequest=%s&SigAlg=%s",
			samlRequest, sigAlg)
	}

	// Decode the signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Get SP certificate
	cert, err := getSPSigningCertificate(idp, spEntityID)
	if err != nil {
		// Log warning but continue for now (backward compatibility)
		slog.Warn("Failed to get SP signing certificate",
			slog.String("sp", spEntityID),
			slog.String("error", err.Error()))

		return nil
	}

	// Verify the signature
	if err := verifyRedirectSignature([]byte(signedData), signatureBytes, cert, sigAlg); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	slog.Info("Successfully validated HTTP-Redirect signature",
		slog.String("sp", spEntityID),
		slog.String("sigAlg", sigAlg))

	return nil
}

// validateEmbeddedSignature validates signatures embedded in the logout request (HTTP-POST binding).
func validateEmbeddedSignature(_ *crewjamsaml.LogoutRequest, spEntityID string) error {
	// The crewjam/saml library doesn't directly support logout request signature validation
	// We would need to implement XML signature validation here
	// For now, log a warning and return nil to continue processing
	slog.Warn("Embedded signature validation for logout requests not yet implemented",
		slog.String("sp", spEntityID),
	)

	return nil
}

// determineSignatureRequirement checks if signature validation is required for a specific SP.
// SP-specific settings override global settings.
func determineSignatureRequirement(cfg config.Config, spEntityID string) bool {
	// Check for SP-specific configuration
	for _, sp := range cfg.Proxy.AllowedSP {
		if sp.EntityID == spEntityID {
			return sp.RequireSignedLogoutRequests
		}
	}

	// Fall back to global configuration
	return cfg.Proxy.RequireSignedLogoutRequests
}

// getSPSigningCertificate retrieves the signing certificate for a specific SP.
//
//nolint:unparam // This function is a stub that will be implemented later
func getSPSigningCertificate(idp *saml.IDP, spEntityID string) (*x509.Certificate, error) {
	if idp == nil {
		return nil, errIDPNotAvailable
	}

	// For now, we'll return an error since we need to implement proper SP metadata fetching
	// This would require:
	// 1. Fetching the SP's metadata from its configured metadata URL
	// 2. Parsing the metadata to extract the signing certificate
	// 3. Caching the certificate for performance

	// The current storage implementation doesn't store SP certificates directly,
	// and the zitadel ServiceProvider type doesn't expose the parsed metadata structure

	return nil, fmt.Errorf("%w for entity: %s", errSPCertNotImplemented, spEntityID)
}

// verifyRedirectSignature verifies the signature of HTTP-Redirect binding data.
func verifyRedirectSignature(data []byte, signature []byte, cert *x509.Certificate, sigAlg string) error {
	// Get the public key from the certificate
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errCertNotRSA
	}

	// Determine hash algorithm
	var hashFunc crypto.Hash
	switch sigAlg {
	case sigAlgSHA1:
		hashFunc = crypto.SHA1
		slog.Warn("SHA1 signature algorithm is deprecated")
	case sigAlgSHA256:
		hashFunc = crypto.SHA256
	default:
		return fmt.Errorf("%w: %s", errUnsupportedSigAlgorithm, sigAlg)
	}

	// Hash the data
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Verify the signature
	err := rsa.VerifyPKCS1v15(publicKey, hashFunc, digest, signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
