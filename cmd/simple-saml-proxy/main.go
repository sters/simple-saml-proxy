package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

func main() {
	ctx := context.Background()

	// Set log level from environment variable
	logLevel := slog.LevelInfo
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		switch level {
		case "debug":
			logLevel = slog.LevelDebug
		case "warn":
			logLevel = slog.LevelWarn
		case "error":
			logLevel = slog.LevelError
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("Failed to process config", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info(
		"config loaded",
		slog.Any("config", cfg),
	)

	providers, err := saml.CreateServiceProviders(ctx, cfg)
	if err != nil {
		slog.Error("Failed to create SAML SPs", slog.Any("error", err))
		os.Exit(1)
	}

	idp, err := saml.CreateProxyIDP(cfg)
	if err != nil {
		slog.Error("Failed to create SAML IDP", slog.Any("error", err))
		os.Exit(1)
	}

	mux := proxy.SetupHTTPHandlers(idp, providers, cfg)

	// Start cleanup goroutine for auth requests
	go startAuthRequestCleanup(idp)

	err = proxy.StartServer(cfg, mux)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}
}

// startAuthRequestCleanup starts a goroutine that periodically cleans up completed auth requests.
func startAuthRequestCleanup(idp *saml.IDP) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Run cleanup immediately on startup
	idp.IDPStorage.CleanupCompletedAuthRequests(10 * time.Minute)

	for range ticker.C {
		idp.IDPStorage.CleanupCompletedAuthRequests(10 * time.Minute)
	}
}
