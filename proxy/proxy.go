package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// SetupHTTPHandlers sets up the HTTP handlers for the SAML proxy.
func SetupHTTPHandlers(providers *SAMLServiceProviders, config Config) http.Handler {
	// Create a custom handler that logs all requests and then delegates to the appropriate handler
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received request", slog.String("path", r.URL.Path))

		// Handle different endpoints
		switch {
		case r.URL.Path == "/metadata":
			// Metadata endpoint
			cookie, err := r.Cookie(config.Proxy.CookieName)
			var idpID string
			if err == nil {
				idpID = cookie.Value
			}
			provider := providers.GetProvider(idpID)
			provider.Middleware.ServeMetadata(w, r)

		case r.URL.Path == "/sso":
			// SSO initiation endpoint
			// Note: RelayState is not currently used, but we might need it in the future
			_ = r.URL.Query().Get("RelayState")
			cookie, err := r.Cookie(config.Proxy.CookieName)
			var idpID string
			if err == nil {
				idpID = cookie.Value
			}
			provider := providers.GetProvider(idpID)
			http.Redirect(w, r, provider.MetadataURL.String(), http.StatusFound)

		case r.URL.Path == "/sso/acs":
			// ACS (Assertion Consumer Service) endpoint
			cookie, err := r.Cookie(config.Proxy.CookieName)
			var idpID string
			if err == nil {
				idpID = cookie.Value
			}
			provider := providers.GetProvider(idpID)
			provider.Middleware.ServeACS(w, r)

		case strings.HasPrefix(r.URL.Path, "/link_sso/"):
			// Link SSO endpoint for IDP selection
			idpID := r.URL.Path[len("/link_sso/"):]
			slog.Info("Link SSO request", slog.String("idp", idpID))

			// Check if the IDP exists
			if _, ok := providers.Providers[idpID]; ok {
				slog.Info("IDP found", slog.String("idp", idpID))

				// Set the cookie with the IDP ID
				cookie := &http.Cookie{
					Name:     config.Proxy.CookieName,
					Value:    idpID,
					Path:     "/",
					HttpOnly: true,
					Secure:   r.TLS != nil,
					SameSite: http.SameSiteLaxMode,
				}
				http.SetCookie(w, cookie)
				slog.Info("Set cookie", slog.String("name", cookie.Name), slog.String("value", cookie.Value))

				// Get the service URL from the query parameter
				serviceURL := r.URL.Query().Get("service")
				if serviceURL == "" {
					serviceURL = "/"
				}
				slog.Info("Service URL", slog.String("url", serviceURL))

				// Redirect to the service URL
				slog.Info("Redirecting", slog.String("url", serviceURL))
				w.Header().Set("Location", serviceURL)
				w.WriteHeader(http.StatusFound)
				slog.Info("Redirect sent", slog.Int("status", http.StatusFound))
			} else {
				slog.Info("Invalid IDP ID", slog.String("idp", idpID))
				http.Error(w, "Invalid IDP ID", http.StatusBadRequest)
			}

		case r.URL.Path == "/ping":
			// Health check endpoint
			_, err := w.Write([]byte("pong"))
			if err != nil {
				slog.Error("Failed to write response", slog.String("error", err.Error()))
			}

		default:
			// 404 for any other path
			http.NotFound(w, r)
		}
	})
}

// StartServer starts the HTTP server with the given configuration and handler.
func StartServer(config Config, handler http.Handler) error {
	server := &http.Server{
		Addr:              config.Server.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("Starting SAML proxy", slog.String("address", config.Server.ListenAddress))
	slog.Info("Metadata URL", slog.String("url", config.Proxy.MetadataURL))
	slog.Info("ACS URL", slog.String("url", config.Proxy.AcsURL))
	slog.Info("SSO URL", slog.String("url", config.Proxy.EntityID+"/sso"))

	// Log information about configured IDP
	slog.Info("Configured IDP")
	for _, idp := range config.IDP {
		slog.Info("IDP details",
			slog.String("entityID", idp.EntityID),
			slog.String("id", idp.ID),
			slog.String("ssoURL", idp.SSOURL),
			slog.String("linkSSOURL", config.Proxy.EntityID+"/link_sso/"+idp.ID))
	}

	err := server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}
