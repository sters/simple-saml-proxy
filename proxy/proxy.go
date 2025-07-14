package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// SetupHTTPHandlers sets up the HTTP handlers for the SAML proxy.
// This proxy acts as a SAML Identity Provider (IdP) proxy:
// - To Service Providers (SPs), it appears as an IdP
// - To Identity Providers (IdPs), it appears as an SP
// It allows users to select which IdP they want to use for authentication.
func SetupHTTPHandlers(idp *saml.IDP, providers *saml.ServiceProviders, _ config.Config) http.Handler {
	mux := http.NewServeMux()

	// Basic endpoints
	mux.HandleFunc("/ping", handlePing)
	mux.Handle("/metadata", idp.IDP.HttpHandler())
	mux.Handle("/sso", handleSSO(idp))
	mux.Handle("/callback", idp.IDP.HttpHandler())

	// SAML proxy endpoints
	mux.HandleFunc("/saml/acs", handleSAMLACS(idp, providers))
	mux.HandleFunc("/idp-initiated", handleIDPInitiated)

	// Single Logout endpoints
	mux.HandleFunc("/slo", handleSLO(idp, providers))
	mux.HandleFunc("/sls", handleSLS(idp, providers))
	mux.HandleFunc("/slo/response", handleSLOResponse(idp, providers))

	// Create request handler with routing
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received request", slog.String("path", r.URL.Path))

		switch {
		case strings.HasPrefix(r.URL.Path, "/idp_selected"):
			handleIDPSelected(idp, providers)(w, r)

			return
		case strings.HasPrefix(r.URL.Path, "/idp_select"):
			handleIDPSelect(idp, providers)(w, r)

			return
		case strings.HasPrefix(r.URL.Path, "/logout_idp_selected"):
			handleLogoutIDPSelected(idp, providers)(w, r)

			return
		case strings.HasPrefix(r.URL.Path, "/logout_idp_select"):
			handleLogoutIDPSelect(idp, providers)(w, r)

			return
		case strings.HasPrefix(r.URL.Path, "/logout_sp_selected"):
			handleLogoutSPSelected(idp, providers)(w, r)

			return
		case strings.HasPrefix(r.URL.Path, "/logout_sp_select"):
			handleLogoutSPSelect(idp, providers)(w, r)

			return
		}

		mux.ServeHTTP(w, r)
	})
}

// StartServer starts the HTTP server with the given configuration and handler.
func StartServer(cfg config.Config, handler http.Handler) error {
	server := &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("Starting SAML IdP proxy", slog.String("address", cfg.Server.ListenAddress))
	slog.Info("Metadata URL (for SPs)", slog.String("url", cfg.Proxy.MetadataURL))
	slog.Info("SSO URL (for SPs)", slog.String("url", cfg.Proxy.EntityID+"/sso"))
	slog.Info("SLO URL (for SPs)", slog.String("url", cfg.Proxy.SLOURL))
	slog.Info("SLO Response URL", slog.String("url", cfg.Proxy.EntityID+"/slo/response"))
	slog.Info("ACS URL (for IdPs)", slog.String("url", cfg.Proxy.AcsURL))
	slog.Info("SLS URL (for IdPs)", slog.String("url", cfg.Proxy.SLSURL))
	slog.Info("IdP Selection URL", slog.String("url", cfg.Proxy.EntityID+"/idp_selected"))

	// Log information about configured IDP
	slog.Info("Configured IDP")
	for _, idp := range cfg.IDP {
		slog.Info("IDP details",
			slog.String("id", idp.ID),
		)
	}

	err := server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}
