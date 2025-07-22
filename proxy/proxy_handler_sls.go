package proxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

var (
	errLogoutRequestIssueInstantInFuture  = errors.New("logout request issue instant is in the future")
	errLogoutRequestIsOld                 = errors.New("logout request is too old")
	errLogoutResponseIssueInstantInFuture = errors.New("logout response issue instant is in the future")
	errLogoutResponseIsOld                = errors.New("logout response is too old")
)

// handleSLS handles Single Logout Service responses and requests.
// This endpoint receives:
// 1. Logout responses from upstream IdPs (for SP-initiated flow)
// 2. Logout requests from upstream IdPs (for IdP-initiated flow).
func handleSLS(idp *saml.IDP, providers *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received SLS request",
			slog.String("method", r.Method),
			slog.String("url", r.URL.String()),
		)

		// Check if this is a response (has SAMLResponse) or request (has SAMLRequest)
		samlResponse := r.URL.Query().Get("SAMLResponse")
		samlRequest := r.URL.Query().Get("SAMLRequest")

		switch {
		case samlResponse != "":
			// Handle logout response from upstream IdP (SP-initiated flow completion)
			handleLogoutResponse(w, r, idp, providers, samlResponse)
		case samlRequest != "":
			// Handle logout request from upstream IdP (IdP-initiated flow)
			handleIDPInitiatedLogout(w, r, idp, providers, samlRequest)
		default:
			slog.Error("No SAMLResponse or SAMLRequest in SLS request")
			http.Error(w, "Invalid request", http.StatusBadRequest)
		}
	}
}

// handleLogoutResponse handles logout responses from upstream IdP.
func handleLogoutResponse(w http.ResponseWriter, r *http.Request, idp *saml.IDP, _ *saml.ServiceProviders, samlResponseParam string) {
	slog.Info("Handling logout response from upstream IdP")

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

	// Parse the logout response
	logoutResponse, err := parseLogoutResponse(samlResponseParam)
	if err != nil {
		slog.Error("Failed to parse logout response", slog.String("error", err.Error()))
		http.Error(w, "Invalid logout response", http.StatusBadRequest)

		return
	}

	// Validate response issue instant
	if err := validateLogoutResponseIssueInstant(logoutResponse.IssueInstant); err != nil {
		slog.Error("Logout response failed time validation",
			slog.String("error", err.Error()),
		)
		http.Error(w, "Invalid logout response", http.StatusBadRequest)

		return
	}

	slog.Info("Parsed logout response",
		slog.String("status", getStatusCode(logoutResponse)),
		slog.String("originSP", logoutCtx.OriginID),
	)

	// Create logout response to send back to the original SP
	finalResponse := &crewjamsaml.LogoutResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: "", // Would be set if we tracked the original request ID
		Version:      "2.0",
		IssueInstant: logoutResponse.IssueInstant,
		Issuer: &crewjamsaml.Issuer{
			Value: idp.IDP.GetEntityID(r.Context()),
		},
		Status: logoutResponse.Status, // Pass through the status from upstream IdP
	}

	// Get the SP's logout response location
	_, err = storage.GetEntityByID(r.Context(), logoutCtx.OriginID)
	if err != nil {
		slog.Error("Failed to get SP entity",
			slog.String("entityID", logoutCtx.OriginID),
			slog.String("error", err.Error()),
		)
		http.Error(w, "Invalid SP", http.StatusInternalServerError)

		return
	}

	// Extract SingleLogoutService from SP metadata
	sls, err := storage.GetSingleLogoutServiceFromSP(r.Context(), logoutCtx.OriginID)
	if err != nil {
		slog.Warn("Failed to extract SingleLogoutService from metadata, using fallback",
			slog.String("entityID", logoutCtx.OriginID),
			slog.String("error", err.Error()))
		// Fallback to the previous hardcoded pattern for backward compatibility
		logoutResponseURL := logoutCtx.OriginID + "/logout/response"
		responseURL, err := buildLogoutResponseURL(finalResponse, logoutResponseURL, logoutCtx.RelayState)
		if err != nil {
			slog.Error("Failed to build fallback logout response URL", slog.String("error", err.Error()))
			http.Error(w, "Failed to create logout response", http.StatusInternalServerError)

			return
		}
		// Redirect to SP with logout response
		slog.Info("Redirecting to SP with logout response (fallback)", slog.String("url", responseURL))
		http.Redirect(w, r, responseURL, http.StatusFound)

		return
	}

	slog.Info("Extracted SingleLogoutService from metadata",
		slog.String("entityID", logoutCtx.OriginID),
		slog.String("binding", sls.Binding),
		slog.String("location", sls.Location))

	// Build the logout response URL using the extracted endpoint
	responseURL, err := buildLogoutResponseURL(finalResponse, sls.Location, logoutCtx.RelayState)
	if err != nil {
		slog.Error("Failed to build logout response URL", slog.String("error", err.Error()))
		http.Error(w, "Failed to create logout response", http.StatusInternalServerError)

		return
	}

	// Clean up the logout context
	storage.DeleteLogoutContext(logoutCtx.ID)

	// Clear cookies
	SetSecureCookie(w, r, "logout_context_id", "", -1)
	SetSecureCookie(w, r, "logout_idp_id", "", -1)

	// Redirect to SP with logout response
	slog.Info("Redirecting to SP with logout response", slog.String("url", responseURL))
	http.Redirect(w, r, responseURL, http.StatusFound)
}

// handleIDPInitiatedLogout handles logout requests from upstream IdP.
func handleIDPInitiatedLogout(w http.ResponseWriter, r *http.Request, idp *saml.IDP, providers *saml.ServiceProviders, samlRequestParam string) {
	slog.Info("Handling IdP-initiated logout request")

	// Parse the logout request from IdP
	logoutRequest, err := parseLogoutRequest(samlRequestParam)
	if err != nil {
		slog.Error("Failed to parse IdP logout request", slog.String("error", err.Error()))
		http.Error(w, "Invalid logout request", http.StatusBadRequest)

		return
	}

	// Validate the request comes from a known IdP
	idpFound := false
	for _, provider := range providers.Providers {
		if provider.Middleware.ServiceProvider.IDPMetadata != nil &&
			provider.Middleware.ServiceProvider.IDPMetadata.EntityID == logoutRequest.Issuer.Value {
			idpFound = true

			break
		}
	}

	if !idpFound {
		slog.Warn("Logout request from unknown IdP",
			slog.String("issuer", logoutRequest.Issuer.Value),
		)
		http.Error(w, "Unknown identity provider", http.StatusForbidden)

		return
	}

	// Check for replay attack - verify IssueInstant is recent
	if err := validateLogoutRequestIssueInstant(logoutRequest.IssueInstant); err != nil {
		slog.Error("IdP logout request failed time validation",
			slog.String("issuer", logoutRequest.Issuer.Value),
			slog.String("error", err.Error()),
		)
		http.Error(w, "Invalid logout request", http.StatusBadRequest)

		return
	}

	// Get the IdP that sent this request (we need to determine this from the request)
	// For now, we'll need to show an SP selection page
	relayState := r.URL.Query().Get("RelayState")

	slog.Info("Parsed IdP-initiated logout request",
		slog.String("issuer", logoutRequest.Issuer.Value),
		slog.String("nameID", getNameIDValue(logoutRequest)),
		slog.String("sessionIndex", getSessionIndex(logoutRequest)),
		slog.String("relayState", relayState),
	)

	// Create a logout context to track this logout flow
	storage := idp.GetStorage()
	logoutCtx := storage.CreateLogoutContext(
		"idp",                      // Origin type
		logoutRequest.Issuer.Value, // Origin ID (IdP entity ID)
		"",                         // Target ID (to be set when SP is selected)
		relayState,                 // Preserve relay state
	)

	// Store the original logout request data in the context for later use
	// We'll need the NameID and SessionIndex when creating logout requests to SPs
	// For now, store in cookies (in production, might want to extend LogoutContext)
	SetSecureCookie(w, r, "logout_context_id", logoutCtx.ID, 300)

	// Store NameID for later use
	if logoutRequest.NameID != nil {
		SetSecureCookie(w, r, "logout_name_id", logoutRequest.NameID.Value, 300)
	}

	// Redirect to SP selection page
	http.Redirect(w, r, "/logout_sp_select", http.StatusFound)
}

// getStatusCode extracts the status code from a logout response.
func getStatusCode(resp *crewjamsaml.LogoutResponse) string {
	if resp.Status.StatusCode.Value != "" {
		return resp.Status.StatusCode.Value
	}

	return "unknown"
}

// validateLogoutRequestIssueInstant checks if the logout request was issued recently to prevent replay attacks.
func validateLogoutRequestIssueInstant(issueInstant time.Time) error {
	const maxAge = 5 * time.Minute

	now := time.Now()
	age := now.Sub(issueInstant)

	if age < 0 {
		// Issue instant is in the future
		return fmt.Errorf("%w: %v", errLogoutRequestIssueInstantInFuture, issueInstant)
	}

	if age > maxAge {
		return fmt.Errorf("%w: issued %v ago", errLogoutRequestIsOld, age)
	}

	return nil
}

// validateLogoutResponseIssueInstant checks if the logout response was issued recently.
func validateLogoutResponseIssueInstant(issueInstant time.Time) error {
	const maxAge = 5 * time.Minute

	now := time.Now()
	age := now.Sub(issueInstant)

	if age < 0 {
		// Issue instant is in the future
		return fmt.Errorf("%w: %v", errLogoutResponseIssueInstantInFuture, issueInstant)
	}

	if age > maxAge {
		return fmt.Errorf("%w: issued %v ago", errLogoutResponseIsOld, age)
	}

	return nil
}
