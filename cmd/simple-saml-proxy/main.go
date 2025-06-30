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

	os.Setenv("PROXY_PRIVATE_KEY_PATH", "/Users/sters/go/src/github.com/sters/simple-saml-proxy/e2e/proxy.key")
	os.Setenv("PROXY_CERTIFICATE_PATH", "/Users/sters/go/src/github.com/sters/simple-saml-proxy/e2e/proxy.crt")
	os.Setenv("PROXY_ALLOWED_SP_0_ENTITY_ID", "urn:example:sp")
	os.Setenv("PROXY_ALLOWED_SP_0_METADATA_URL", "http://localhost:7070/metadata")
	os.Setenv("IDP_0_ID", "SAMLKit1")
	os.Setenv("IDP_0_ENTITY_ID", "https://samlkit.com/saml2/idp/adhoc")
	os.Setenv("IDP_0_SSO_URL", "https://samlkit.com/saml2/receive")
	os.Setenv("IDP_0_CERTIFICATE_PATH", "/Users/sters/go/src/github.com/sters/simple-saml-proxy/e2e/samlkit1.crt")
	os.Setenv("SERVER_LISTEN_ADDRESS", "localhost:8080")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	config, err := proxy.LoadConfig()
	if err != nil {
		slog.Error("Failed to process config", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info(
		"config loaded",
		slog.Any("config", config),
	)

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
