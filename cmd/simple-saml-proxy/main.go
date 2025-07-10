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

	// for debug
	os.Setenv("PROXY_PRIVATE_KEY_PATH", "/Users/sters/go/src/github.com/sters/simple-saml-proxy/e2e/proxy.key")
	os.Setenv("PROXY_CERTIFICATE_PATH", "/Users/sters/go/src/github.com/sters/simple-saml-proxy/e2e/proxy.crt")
	os.Setenv("PROXY_ALLOWED_SP_0_ENTITY_ID", "urn:example:sp")
	os.Setenv("PROXY_ALLOWED_SP_0_METADATA_URL", "http://localhost:7070/metadata")
	os.Setenv("IDP_0_ID", "SAMLKit1")
	os.Setenv("IDP_0_ENTITY_ID", "https://samlkit.com/saml2/idp/adhoc")
	os.Setenv("IDP_0_SSO_URL", "https://samlkit.com/saml2/receive")
	os.Setenv("IDP_0_CERTIFICATE_PATH", "/Users/sters/go/src/github.com/sters/simple-saml-proxy/e2e/samlkit1.crt")
	os.Setenv("IDP_1_ID", "local saml-idp")
	os.Setenv("IDP_1_METADATA_URL", "http://localhost:7000/metadata")
	os.Setenv("SERVER_LISTEN_ADDRESS", "localhost:8080")

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
