package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/sters/simple-saml-proxy/proxy"
)

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

	// Create SAML Service Providers for all IDP
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
