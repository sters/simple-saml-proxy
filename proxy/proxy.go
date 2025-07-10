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
	mux.Handle("/sso", idp.IDP.HttpHandler())
	mux.Handle("/callback", idp.IDP.HttpHandler())

	// SAML proxy endpoints
	mux.HandleFunc("/saml/acs", handleSAMLACS(idp, providers))
	mux.HandleFunc("/idp-initiated", handleIDPInitiated)

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
		}

		mux.ServeHTTP(w, r)
	})
}

// isAllowedServiceURL checks if the given service URL is allowed based on the prefix match configuration.
// If no allowed prefixes are configured, all service URLs are allowed.
func isAllowedServiceURL(serviceURL string, allowedPrefixes []string) bool {
	// If no allowed prefixes are configured, allow all service URLs
	if len(allowedPrefixes) == 0 {
		return true
	}

	// Check if the service URL starts with any of the allowed prefixes
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(serviceURL, prefix) {
			return true
		}
	}

	return false
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
	slog.Info("ACS URL (for IdPs)", slog.String("url", cfg.Proxy.AcsURL))
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
