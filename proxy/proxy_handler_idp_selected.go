package proxy

import (
	"encoding/base64"
	"log/slog"
	"net/http"
)

// handleIDPSelected handles the IdP selection result and redirects to the selected IdP.
func handleIDPSelected(idp *IDP, providers *ServiceProviders) http.HandlerFunc {
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

		authRequest, err := idp.idpStorage.AuthRequestByID(r.Context(), authRequestID)
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

		http.SetCookie(w, &http.Cookie{
			Name:     cookieNameIDPID,
			Value:    idpID,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecureCookie(r),
		})

		slog.Info("IDP found", slog.String("idp", idpID))

		// Use original relay state from auth request if available
		var relayState string
		if ar, ok := authRequest.(*AuthRequest); ok && ar.RelayState != "" {
			relayState = ar.RelayState
		} else {
			relayState = base64.RawURLEncoding.EncodeToString(randomBytes(relayStateLength))
		}
		redirectURL, err := provider.Middleware.ServiceProvider.MakeRedirectAuthenticationRequest(relayState)
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
