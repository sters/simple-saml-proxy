package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/sters/simple-saml-proxy/proxy"
)

func main() {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	config, err := proxy.LoadConfig()
	if err != nil {
		slog.Error("Failed to process config", slog.Any("error", err))
		os.Exit(1)
	}

	providers, err := proxy.CreateServiceProviders(ctx, config)
	if err != nil {
		slog.Error("Failed to create SAML SPs", slog.Any("error", err))
		os.Exit(1)
	}

	idp, err := proxy.CreateProxyIDP(config)
	if err != nil {
		slog.Error("Failed to create SAML IDP", slog.Any("error", err))
		os.Exit(1)
	}

	mux := proxy.SetupHTTPHandlers(idp, providers, config)

	err = proxy.StartServer(config, mux)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}
}
