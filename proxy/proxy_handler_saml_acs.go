package proxy

import (
	"log/slog"
	"net/http"

	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// handleSAMLACS handles the SAML assertion consumer service endpoint.
func handleSAMLACS(idp *saml.IDP, providers *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Processing SAML response from actual IdP")

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

		if ar, ok := authRequest.(*saml.AuthRequest); ok {
			ar.IsDone = true // 自分でDone=trueにしないといけない
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

		callbackURL := idp.IDP.AuthCallbackURL()(r.Context(), authRequestID)
		http.Redirect(w, r, callbackURL, http.StatusFound)
	}
}
