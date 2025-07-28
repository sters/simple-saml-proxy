package proxy

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

const (
	sigAlgSHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sigAlgSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

var (
	errLogoutRequestSignatureRequired = errors.New("logout request signature is required but not present")
	errIDPNotAvailable                = errors.New("IDP not available")
	errCertNotRSA                     = errors.New("certificate does not contain an RSA public key")
	errUnsupportedSigAlgorithm        = errors.New("unsupported signature algorithm")
	errLogoutRequestElementNotFound   = errors.New("failed to get logout request element")
	errStorageNotAvailable            = errors.New("storage not available")
)

// handleSLO handles Single Logout requests initiated by Service Providers.
// Flow: SP → Proxy → Upstream IdP.
func handleSLO(idp *saml.IDP, _ *saml.ServiceProviders, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received SLO request from SP",
			slog.String("method", r.Method),
			slog.String("url", r.URL.String()),
		)

		var samlRequestParam string
		var relayState string

		// Handle different bindings based on HTTP method
		switch r.Method {
		case http.MethodGet:
			// HTTP-Redirect binding
			samlRequestParam = r.URL.Query().Get("SAMLRequest")
			relayState = r.URL.Query().Get("RelayState")
		case http.MethodPost:
			// HTTP-POST binding
			// Parse form data
			if err := r.ParseForm(); err != nil {
				slog.Error("Failed to parse form data", slog.String("error", err.Error()))
				respondWithBadRequest(w, ErrInvalidFormData)

				return
			}
			samlRequestParam = r.FormValue("SAMLRequest")
			relayState = r.FormValue("RelayState")
		default:
			slog.Error("Unsupported HTTP method for SLO", slog.String("method", r.Method))
			respondWithMethodNotAllowed(w)

			return
		}

		if samlRequestParam == "" {
			slog.Error("No SAMLRequest parameter in logout request")
			respondWithBadRequest(w, ErrMissingSAMLRequest)

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
		if err := validateLogoutRequestSignature(r.Context(), logoutRequest, idp, logoutRequest.Issuer.Value, r.URL.RawQuery, requireSignature); err != nil {
			slog.Error("Logout request signature validation failed",
				slog.String("issuer", logoutRequest.Issuer.Value),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid logout request signature", http.StatusBadRequest)

			return
		}
		_ = sp // Mark as used for future enhanced validation

		// Check for replay attack - verify IssueInstant is recent
		if err := validateSAMLIssueInstant(logoutRequest.IssueInstant, "logout request"); err != nil {
			slog.Error("Logout request failed time validation",
				slog.String("issuer", logoutRequest.Issuer.Value),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		slog.Info("Parsed logout request",
			slog.String("issuer", logoutRequest.Issuer.Value),
			slog.String("nameID", getNameIDValue(logoutRequest)),
			slog.String("sessionIndex", getSessionIndex(logoutRequest)),
			slog.String("relayState", relayState),
			slog.String("binding", getBindingType(r)),
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
		SetSecureCookie(w, r, "logout_context_id", logoutCtx.ID, 300)

		// For now, redirect to IdP selection page
		// In a production implementation, you might track which IdP was used for login
		http.Redirect(w, r, "/logout_idp_select", http.StatusFound)
	}
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

// validateLogoutRequestSignature validates the signature of a logout request.
// For HTTP-Redirect binding, it validates query parameter signatures.
// For HTTP-POST binding, it validates embedded signatures.
func validateLogoutRequestSignature(
	ctx context.Context,
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
		return validateRedirectSignature(ctx, rawQuery, idp, spEntityID)
	}

	// For HTTP-POST binding with embedded signature
	if logoutRequest.Signature != nil {
		return validateEmbeddedSignature(ctx, logoutRequest, idp, spEntityID)
	}

	return nil
}

// validateRedirectSignature validates signatures passed as query parameters in HTTP-Redirect binding.
func validateRedirectSignature(ctx context.Context, rawQuery string, idp *saml.IDP, spEntityID string) error {
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
	cert, err := getSPSigningCertificate(ctx, idp, spEntityID)
	if err != nil {
		return fmt.Errorf("failed to get SP signing certificate: %w", err)
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
func validateEmbeddedSignature(ctx context.Context, logoutRequest *crewjamsaml.LogoutRequest, idp *saml.IDP, spEntityID string) error {
	// Check if signature element exists
	if logoutRequest.Signature == nil {
		return nil
	}

	// Get the logout request as an etree element
	requestElement := logoutRequest.Element()
	if requestElement == nil {
		return errLogoutRequestElementNotFound
	}

	// Get SP certificate for signature validation
	cert, err := getSPSigningCertificate(ctx, idp, spEntityID)
	if err != nil {
		return fmt.Errorf("failed to get SP signing certificate: %w", err)
	}

	// Create certificate store with the SP's certificate
	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}

	// Create validation context
	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	if crewjamsaml.Clock != nil {
		validationContext.Clock = crewjamsaml.Clock
	}

	// Build parent context for proper namespace handling
	nsCtx, err := etreeutils.NSBuildParentContext(requestElement)
	if err != nil {
		return fmt.Errorf("failed to build parent context: %w", err)
	}

	// Build sub-context for the element
	nsCtx, err = nsCtx.SubContext(requestElement)
	if err != nil {
		return fmt.Errorf("failed to build sub-context: %w", err)
	}

	// Detach the element with proper namespace handling
	detachedElement, err := etreeutils.NSDetatch(nsCtx, requestElement)
	if err != nil {
		return fmt.Errorf("failed to detach element: %w", err)
	}

	// Validate the signature
	if _, err := validationContext.Validate(detachedElement); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	slog.Info("Successfully validated embedded XML signature",
		slog.String("sp", spEntityID))

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
func getSPSigningCertificate(ctx context.Context, idp *saml.IDP, spEntityID string) (*x509.Certificate, error) {
	if idp == nil {
		return nil, errIDPNotAvailable
	}

	storage := idp.GetStorage()
	if storage == nil {
		return nil, errStorageNotAvailable
	}

	// Get the certificate from metadata using the cache
	cache := storage.GetSPCertificateCache()
	cert, err := saml.GetSPSigningCertificateFromMetadata(ctx, storage.GetConfig(), spEntityID, cache)
	if err != nil {
		return nil, fmt.Errorf("failed to get SP signing certificate: %w", err)
	}

	return cert, nil
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

// getBindingType determines the SAML binding type based on the HTTP request.
func getBindingType(r *http.Request) string {
	if r.Method == http.MethodPost {
		return "HTTP-POST"
	}

	return "HTTP-Redirect"
}
