package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// handleSLOResponse handles logout responses from SPs in the IdP-initiated flow.
// This completes the IdP-initiated logout by sending a response back to the originating IdP.
func handleSLOResponse(idp *saml.IDP, _ *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received logout response from SP",
			slog.String("method", r.Method),
			slog.String("url", r.URL.String()),
		)

		// Get the SAMLResponse parameter
		samlResponseParam := r.URL.Query().Get("SAMLResponse")
		if samlResponseParam == "" {
			slog.Error("No SAMLResponse parameter in logout response")
			http.Error(w, "Missing SAMLResponse parameter", http.StatusBadRequest)

			return
		}

		// Parse the logout response from SP
		logoutResponse, err := parseLogoutResponse(samlResponseParam)
		if err != nil {
			slog.Error("Failed to parse SP logout response", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout response", http.StatusBadRequest)

			return
		}

		// Validate response issue instant
		if err := validateSAMLIssueInstant(logoutResponse.IssueInstant, "logout response"); err != nil {
			slog.Error("SP logout response failed time validation",
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid logout response", http.StatusBadRequest)

			return
		}

		// Get logout context from cookie
		logoutCtxCookie, err := r.Cookie("logout_context_id")
		if err != nil {
			slog.Error("Failed to get logout context cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout response", http.StatusBadRequest)

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
			http.Error(w, "Invalid logout response", http.StatusBadRequest)

			return
		}

		slog.Info("Parsed SP logout response",
			slog.String("status", getLogoutResponseStatus(logoutResponse)),
			slog.String("originIdP", logoutCtx.OriginID),
			slog.String("targetSP", logoutCtx.TargetID),
		)

		// Create logout response to send back to the originating IdP
		finalResponse := &crewjamsaml.LogoutResponse{
			ID:           fmt.Sprintf("id-%x", randomBytes(20)),
			InResponseTo: "", // Would be set if we tracked the original request ID
			Version:      "2.0",
			IssueInstant: logoutResponse.IssueInstant,
			Issuer: &crewjamsaml.Issuer{
				Value: idp.IDP.GetEntityID(r.Context()),
			},
			Status: logoutResponse.Status, // Pass through the status from SP
		}

		// Determine where to send the response based on the logout flow type
		responseURL := getLogoutResponseURL(r.Context(), storage, logoutCtx)

		// Build the logout response URL
		redirectURL, err := buildLogoutResponseURL(finalResponse, responseURL, logoutCtx.RelayState)
		if err != nil {
			slog.Error("Failed to build logout response URL", slog.String("error", err.Error()))
			http.Error(w, "Failed to create logout response", http.StatusInternalServerError)

			return
		}

		// Clean up the logout context
		storage.DeleteLogoutContext(logoutCtx.ID)

		// Clear cookies
		SetSecureCookie(w, r, "logout_context_id", "", -1)
		SetSecureCookie(w, r, "logout_sp_id", "", -1)
		SetSecureCookie(w, r, "logout_name_id", "", -1)

		// Redirect to IdP with logout response
		slog.Info("Redirecting to IdP with logout response", slog.String("url", redirectURL))
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// getLogoutResponseStatus extracts the status code from a logout response.
func getLogoutResponseStatus(resp *crewjamsaml.LogoutResponse) string {
	if resp.Status.StatusCode.Value != "" {
		return resp.Status.StatusCode.Value
	}

	return "unknown"
}

// buildLogoutResponseURL creates the logout response URL with encoded SAML response.
func buildLogoutResponseURL(logoutResponse *crewjamsaml.LogoutResponse, destination string, relayState string) (string, error) {
	// Marshal the logout response
	doc := etree.NewDocument()
	doc.SetRoot(logoutResponse.Element())
	xmlBytes, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("failed to marshal logout response: %w", err)
	}

	// Compress using deflate
	compressed, err := deflateCompress([]byte(xmlBytes))
	if err != nil {
		return "", fmt.Errorf("failed to compress logout response: %w", err)
	}

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(compressed)

	// Build URL
	responseURL, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("failed to parse destination URL: %w", err)
	}

	query := responseURL.Query()
	query.Set("SAMLResponse", encoded)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	responseURL.RawQuery = query.Encode()

	return responseURL.String(), nil
}

// getLogoutResponseURL determines the appropriate URL to send logout response to.
func getLogoutResponseURL(ctx context.Context, storage *saml.Storage, logoutCtx *saml.LogoutContext) string {
	if logoutCtx.OriginType != "sp" {
		// IdP-initiated flow: send response back to the IdP
		// For now, we'll use a standard pattern
		return logoutCtx.OriginID + "/slo/response"
	}

	// SP-initiated flow: send response back to the SP
	// Try to get the SingleLogoutService from SP metadata
	sls, err := storage.GetSingleLogoutServiceFromSP(ctx, logoutCtx.OriginID)
	if err != nil {
		slog.Warn("Failed to extract SingleLogoutService from SP metadata, using fallback",
			slog.String("entityID", logoutCtx.OriginID),
			slog.String("error", err.Error()))
		// Fallback to standard pattern
		return logoutCtx.OriginID + "/logout/response"
	}

	// Use ResponseLocation if available, otherwise use Location
	if sls.ResponseLocation != "" {
		return sls.ResponseLocation
	}

	return sls.Location
}
