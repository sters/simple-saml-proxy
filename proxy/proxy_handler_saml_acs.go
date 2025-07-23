package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	crewjamSaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/config"
	proxySaml "github.com/sters/simple-saml-proxy/proxy/saml"
)

// handleSAMLACS handles the SAML assertion consumer service endpoint.
func handleSAMLACS(idp *proxySaml.IDP, providers *proxySaml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Processing SAML response from actual IdP")

		// Check if this is an IdP-initiated flow (no cookies)
		authRequestIDCookie, err := r.Cookie(cookieNameAuthRequestID)
		isIDPInitiated := err == http.ErrNoCookie
		
		if isIDPInitiated {
			slog.Info("Detected IdP-initiated flow")
			// For IdP-initiated flow, we need to handle the response differently
			handleIDPInitiatedFlow(w, r, idp, providers)
			return
		}
		
		if err != nil {
			slog.Error("Failed to get auth request ID cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		authRequestID := authRequestIDCookie.Value
		if authRequestID == "" {
			slog.Error("Auth request ID cookie is empty")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		authRequest, err := idp.IDPStorage.AuthRequestByID(r.Context(), authRequestID)
		if err != nil {
			// If auth request doesn't exist, create one manually
			// This can happen when the flow bypasses the normal zitadel/saml auth request creation
			slog.Info("Auth request not found, creating one manually",
				slog.String("id", authRequestID),
				slog.String("error", err.Error()),
			)

			// Create a minimal auth request for the callback
			authRequest = &proxySaml.AuthRequest{
				ID:     authRequestID,
				UserID: "unknown", // Will be updated with actual user info
				IsDone: false,
			}

			// Store it in the storage for the callback to find
			storage := idp.GetStorage()
			if ar, ok := authRequest.(*proxySaml.AuthRequest); ok {
				storage.AddAuthRequestForTesting(ar)
			}
		}

		if ar, ok := authRequest.(*proxySaml.AuthRequest); ok {
			ar.IsDone = true // 自分でDone=trueにしないといけない
			ar.CompletedAt = time.Now()
		} else {
			slog.Error("Failed to cast authRequest to *AuthRequest")
			http.Error(w, "Invalid request", http.StatusInternalServerError)

			return
		}

		idpIDCookie, err := r.Cookie(cookieNameIDPID)
		if err != nil {
			slog.Error("Failed to get IDP ID cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		idpID := idpIDCookie.Value
		if idpID == "" {
			slog.Error("IDP ID cookie is empty")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		provider, ok := providers.Providers[idpID]
		if !ok {
			slog.Error("Invalid IDP ID", slog.String("idp", idpID))
			http.Error(w, "Invalid IDP ID", http.StatusBadRequest)

			return
		}

		if err := r.ParseForm(); err != nil {
			slog.Error("Failed to parse form", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		trackedRequests := provider.Middleware.RequestTracker.GetTrackedRequests(r)
		possibleRequestIDs := make([]string, len(trackedRequests))
		for i, tr := range trackedRequests {
			possibleRequestIDs[i] = tr.SAMLRequestID
		}

		// If no tracked requests, allow any request ID (for manual auth request creation)
		if len(possibleRequestIDs) == 0 {
			slog.Info("No tracked requests found, allowing any request ID")
			possibleRequestIDs = nil
		}

		assertion, err := provider.Middleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
		if err != nil {
			slog.Error("Failed to parse response", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		slog.Info(
			"Assertion",
			slog.Any("subject", assertion.Subject),
			slog.Any("attributes", assertion.AttributeStatements),
		)

		if assertion.Subject == nil || assertion.Subject.NameID == nil {
			slog.Error("Assertion does not contain NameID")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		// Store the assertion in the auth request
		if ar, ok := authRequest.(*proxySaml.AuthRequest); ok {
			ar.Assertion = assertion
			// Update the UserID with the actual NameID from the assertion
			ar.UserID = assertion.Subject.NameID.Value
		}

		callbackURL := idp.IDP.AuthCallbackURL()(r.Context(), authRequestID)
		slog.Info("Redirecting to callback URL",
			slog.String("url", callbackURL),
			slog.String("authRequestID", authRequestID),
		)
		http.Redirect(w, r, callbackURL, http.StatusFound)
	}
}

// handleIDPInitiatedFlow handles IdP-initiated SAML flow where the user starts at the IdP
func handleIDPInitiatedFlow(w http.ResponseWriter, r *http.Request, idp *proxySaml.IDP, providers *proxySaml.ServiceProviders) {
	slog.Info("Handling IdP-initiated flow")

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", slog.String("error", err.Error()))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// In IdP-initiated flow, we don't know which IdP sent the response
	// We need to try parsing with each configured provider
	var assertion *crewjamSaml.Assertion
	var providerID string
	var parseErr error

	for id, provider := range providers.Providers {
		slog.Info("Trying to parse response with provider", slog.String("provider_id", id))
		
		// Try to parse the response without checking request IDs (IdP-initiated)
		assertion, parseErr = provider.Middleware.ServiceProvider.ParseResponse(r, nil)
		if parseErr == nil {
			providerID = id
			slog.Info("Successfully parsed response", slog.String("provider_id", id))
			break
		}
		slog.Debug("Failed to parse with provider", 
			slog.String("provider_id", id), 
			slog.String("error", parseErr.Error()))
	}

	if assertion == nil {
		slog.Error("Failed to parse response with any provider", slog.String("error", parseErr.Error()))
		http.Error(w, "Invalid SAML response", http.StatusBadRequest)
		return
	}

	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		slog.Error("Assertion does not contain NameID")
		http.Error(w, "Invalid SAML response", http.StatusBadRequest)
		return
	}

	slog.Info("IdP-initiated assertion received",
		slog.String("subject", assertion.Subject.NameID.Value),
		slog.String("provider", providerID),
		slog.Any("attributes", assertion.AttributeStatements))

	// Store the assertion data in a temporary storage with a unique ID
	sessionID := generateRandomID()
	
	// Create a minimal auth request for SP selection
	authRequest := &proxySaml.AuthRequest{
		ID:          sessionID,
		UserID:      assertion.Subject.NameID.Value,
		IsDone:      true,
		CompletedAt: time.Now(),
		Assertion:   assertion,
		// These will be filled when SP is selected
		ApplicationID:            "",
		AccessConsumerServiceURL: "",
		Issuer:                   "",
		RelayState:               "",
		BindingType:              "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	}
	
	// Store in the IDP storage
	storage := idp.GetStorage()
	storage.AddAuthRequestForTesting(authRequest)

	// If there's only one allowed SP, redirect directly to it
	allowedSPs := storage.GetAllowedSPs()
	if len(allowedSPs) == 1 {
		slog.Info("Single SP configured, redirecting directly")
		
		// Create SAML response for the SP
		sp := allowedSPs[0]
		redirectToSPWithAssertion(w, r, idp, sp, assertion, sessionID)
		return
	}

	// Multiple SPs configured, show SP selection page
	slog.Info("Multiple SPs configured, showing SP selection page")
	
	// Set cookies for SP selection
	http.SetCookie(w, &http.Cookie{
		Name:     "idp_initiated_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})
	
	http.SetCookie(w, &http.Cookie{
		Name:     "idp_initiated_provider",
		Value:    providerID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	// Redirect to SP selection page
	selectURL := fmt.Sprintf("%s/sp_select", idp.EntityID)
	http.Redirect(w, r, selectURL, http.StatusFound)
}

// redirectToSPWithAssertion creates a SAML response and redirects to the SP
func redirectToSPWithAssertion(w http.ResponseWriter, r *http.Request, idp *proxySaml.IDP, sp config.SPConfig, assertion *crewjamSaml.Assertion, sessionID string) {
	slog.Info("Creating SAML response for IdP-initiated flow",
		slog.String("sp_entity_id", sp.EntityID),
		slog.String("sp_acs_url", sp.AcsURL),
		slog.String("session_id", sessionID))
	
	// Update the auth request with SP information
	storage := idp.GetStorage()
	authRequest, err := storage.AuthRequestByID(r.Context(), sessionID)
	if err != nil {
		slog.Error("Failed to get auth request", slog.String("error", err.Error()))
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}
	
	if ar, ok := authRequest.(*proxySaml.AuthRequest); ok {
		ar.Issuer = sp.EntityID
		ar.AccessConsumerServiceURL = sp.AcsURL
		ar.ApplicationID = sp.EntityID
		
		// The entity ID mapping is handled by the storage
	}
	
	// For IdP-initiated flow, we use the callback URL mechanism
	// The auth request is already stored with the assertion
	callbackURL := idp.IDP.AuthCallbackURL()(r.Context(), sessionID)
	
	slog.Info("Redirecting to callback URL for IdP-initiated flow",
		slog.String("url", callbackURL))
	
	http.Redirect(w, r, callbackURL, http.StatusFound)
}
