package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

func main() {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
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

	err = proxy.StartServer(cfg, mux)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}
}
