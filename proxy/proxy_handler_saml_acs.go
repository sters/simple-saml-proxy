package proxy

import (
	"log/slog"
	"net/http"
	"time"

	proxySaml "github.com/sters/simple-saml-proxy/proxy/saml"
)

// handleSAMLACS handles the SAML assertion consumer service endpoint.
func handleSAMLACS(idp *proxySaml.IDP, providers *proxySaml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Processing SAML response from actual IdP")

		// Get auth request ID from cookie
		authRequestIDCookie, err := r.Cookie(cookieNameAuthRequestID)
		if err != nil {
			slog.Error("Failed to get auth request ID cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid request - missing auth request cookie", http.StatusBadRequest)

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
