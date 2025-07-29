package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// SetupHTTPHandlers sets up the HTTP handlers for the SAML proxy.
// This proxy acts as a SAML Identity Provider (IdP) proxy:
// - To Service Providers (SPs), it appears as an IdP
// - To Identity Providers (IdPs), it appears as an SP
// It allows users to select which IdP they want to use for authentication.
func SetupHTTPHandlers(idp *saml.IDP, providers *saml.ServiceProviders, cfg config.Config) http.Handler {
	mux := http.NewServeMux()

	loggingHandler := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Received request", slog.String("path", r.URL.Path))
			h.ServeHTTP(w, r)
		})
	}

	mux.HandleFunc("/ping", handlePing)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)

			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("SAML Proxy is running")); err != nil {
			slog.Error("Failed to write response", slog.String("error", err.Error()))
		}
	})

	mux.HandleFunc("/idp/slo", handleSLO(idp, providers, cfg))
	mux.HandleFunc("/idp/slo/response", handleSLOResponse(idp, providers, cfg))
	mux.HandleFunc("/idp/idp_select", handleIDPSelect(idp, providers))
	mux.HandleFunc("/idp/idp_selected", handleIDPSelected(idp, providers))

	mux.Handle("/idp/", idp.IDP.HttpHandler())

	mux.HandleFunc("/sp/acs", handleSAMLACS(idp, providers))
	mux.HandleFunc("/sp/sls", handleSLS(idp, providers))
	mux.HandleFunc("/sp/idp_select", handleIDPSelect(idp, providers))
	mux.HandleFunc("/sp/idp_selected", handleIDPSelected(idp, providers))
	mux.HandleFunc("/sp/logout_idp_select", handleLogoutIDPSelect(idp, providers))
	mux.HandleFunc("/sp/logout_idp_selected", handleLogoutIDPSelected(idp, providers))
	mux.HandleFunc("/sp/logout_sp_select", handleLogoutSPSelect(idp, providers))
	mux.HandleFunc("/sp/logout_sp_selected", handleLogoutSPSelected(idp, providers))

	return loggingHandler(mux)
}

// StartServer starts the HTTP server with the given configuration and handler.
func StartServer(cfg config.Config, handler http.Handler) error {
	server := &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	err := server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}
