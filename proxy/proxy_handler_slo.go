package proxy

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

var (
	errLogoutRequestMissingIssuer      = errors.New("logout request missing issuer")
	errLogoutRequestIssueInstantFuture = errors.New("logout request issue instant is in the future")
	errLogoutRequestTooOld             = errors.New("logout request is too old")
)

// handleSLO handles Single Logout requests initiated by Service Providers.
// Flow: SP → Proxy → Upstream IdP.
func handleSLO(idp *saml.IDP, _ *saml.ServiceProviders) http.HandlerFunc {
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

		// Signature validation not implemented yet (tracked in issue #27)
		// For now, we accept unsigned logout requests (common with HTTP-Redirect binding)
		if logoutRequest.Signature != nil {
			slog.Warn("Logout request signature validation not implemented",
				slog.String("issuer", logoutRequest.Issuer.Value),
			)
		}
		_ = sp // Mark as used for future signature validation

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
