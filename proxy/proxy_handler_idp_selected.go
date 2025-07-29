package proxy

import (
	"encoding/base64"
	"log/slog"
	"net/http"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// handleIDPSelected handles the IdP selection result and redirects to the selected IdP.
func handleIDPSelected(idp *saml.IDP, providers *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authRequestIDCookie, err := r.Cookie(cookieNameAuthRequestID)
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
			slog.Error("Failed to get auth request",
				slog.String("id", authRequestID),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid request", http.StatusInternalServerError)

			return
		}

		idpID := r.FormValue("idpID")
		slog.Info("IdP selection",
			slog.String("idp", idpID),
			slog.Any("query", r.URL.Query()),
		)

		provider, ok := providers.Providers[idpID]
		if !ok {
			slog.Info("Invalid IDP ID", slog.String("idp", idpID))
			http.Error(w, "Invalid IDP ID", http.StatusBadRequest)

			return
		}

		SetSecureCookie(w, r, cookieNameIDPID, idpID, 300)

		slog.Info("IDP found", slog.String("idp", idpID))

		// Use original relay state from auth request if available
		var relayState string
		if ar, ok := authRequest.(*saml.AuthRequest); ok && ar.RelayState != "" {
			relayState = ar.RelayState
		} else {
			relayState = base64.RawURLEncoding.EncodeToString(randomBytes(relayStateLength))
		}

		// Create the authentication request manually to fix entity ID issue
		idpSSOURL := provider.Middleware.ServiceProvider.GetSSOBindingLocation(crewjamsaml.HTTPRedirectBinding)
		authReq, err := provider.Middleware.ServiceProvider.MakeAuthenticationRequest(idpSSOURL, crewjamsaml.HTTPRedirectBinding, crewjamsaml.HTTPPostBinding)
		if err != nil {
			slog.Error("Failed to create auth request", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}

		// Override the issuer to use the correct entity ID (without /saml/metadata suffix)
		slog.Info("Original issuer", slog.String("issuer", authReq.Issuer.Value))
		authReq.Issuer.Value = idp.EntityID
		slog.Info("Updated issuer", slog.String("issuer", authReq.Issuer.Value))

		// Log the ACS URL being used
		slog.Info("ACS URL in SAML request", slog.String("acs_url", authReq.AssertionConsumerServiceURL))

		// Create redirect URL with the modified auth request
		redirectURL, err := authReq.Redirect(relayState, &provider.Middleware.ServiceProvider)
		if err != nil {
			slog.Error("Failed to create redirect URL", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}

		w.Header().Add("Location", redirectURL.String())
		w.WriteHeader(http.StatusFound)

		slog.Info("Redirecting to IdP", slog.String("url", redirectURL.String()))
	}
}
