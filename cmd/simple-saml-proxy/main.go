package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/sters/simple-saml-proxy/proxy"
)

// This SAML proxy supports multiple IDPs with the following flow:
// 1. Browser accesses /link_sso/{idp_id} which sets a cookie to identify the IDP and redirects to the service URL
// 2. Browser redirects to the service URL and initiates SAML SSO
// 3. Browser accesses the proxy, the IDP is determined from the cookie, and redirects to the IDP
// 4. Browser accesses the IDP for authentication/authorization and redirects back to the proxy
// 5. Browser opens the proxy, which redirects to the service
// 6. Browser opens the service, is authenticated, and can access the service

func main() {
	// Initialize the default logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration
	config, err := proxy.LoadConfig()
	if err != nil {
		slog.Error("Failed to process config", slog.Any("error", err))
		os.Exit(1)
	}

	// Load certificates
	keyPair, err := proxy.LoadCertificate(config.Proxy.CertificatePath, config.Proxy.PrivateKeyPath)
	if err != nil {
		slog.Error("Failed to load SP certificate and key", slog.Any("error", err))
		os.Exit(1)
	}

	// Create SAML Service Providers for all IDPs
	providers, err := proxy.CreateSAMLServiceProviders(config, keyPair)
	if err != nil {
		slog.Error("Failed to create SAML SPs", slog.Any("error", err))
		os.Exit(1)
	}

	// Set up HTTP handlers
	mux := proxy.SetupHTTPHandlers(providers, config)

	// Start the server
	err = proxy.StartServer(config, mux)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}
}
