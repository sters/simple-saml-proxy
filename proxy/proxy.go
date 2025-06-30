package proxy

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// idpSelectionTemplate is the HTML template for the IdP selection page
const idpSelectionTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Select Identity Provider</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .idp-list { margin-top: 20px; }
        .idp-button {
            display: block;
            margin: 10px 0;
            padding: 10px 15px;
            background-color: #f0f0f0;
            border: 1px solid #ddd;
            border-radius: 4px;
            text-decoration: none;
            color: #333;
            width: 300px;
        }
        .idp-button:hover {
            background-color: #e0e0e0;
        }
    </style>
	<script>
		const onClick = (id) => {
			const url = "{{$.SelectURL}}/" + id;
			window.location.href = url + location.search;
			return false;
		};
	</script>
</head>
<body>
    <h1>Select an Identity Provider</h1>
    <div class="idp-list">
        {{range .Providers}}
        <a href="#" class="idp-button" onclick="onClick('{{.ID}}')">
            {{.ID}}
        </a>
        {{end}}
    </div>
</body>
</html>
`

// handlePing handles the /ping health check endpoint
func handlePing(w http.ResponseWriter, r *http.Request) {
	// Health check endpoint
	_, err := w.Write([]byte("pong"))
	if err != nil {
		slog.Error("Failed to write response", slog.String("error", err.Error()))
	}
}

// SetupHTTPHandlers sets up the HTTP handlers for the SAML proxy.
// This proxy acts as a SAML Identity Provider (IdP) proxy:
// - To Service Providers (SPs), it appears as an IdP
// - To Identity Providers (IdPs), it appears as an SP
// It allows users to select which IdP they want to use for authentication.
func SetupHTTPHandlers(idp *IDP, providers *ServiceProviders, config Config) http.Handler {
	// Create a router to handle different paths
	mux := http.NewServeMux()

	mux.HandleFunc("/ping", handlePing)
	mux.Handle("/metadata", idp.idp.HttpHandler())
	mux.Handle("/sso", idp.idp.HttpHandler())

	idpSelectHandler := func(w http.ResponseWriter, _ *http.Request) {
		data := struct {
			Providers map[string]*ServiceProvider
			SelectURL string
		}{
			Providers: providers.Providers,
			SelectURL: "/idp_selected",
		}

		// Parse the IdP selection template
		tmpl, err := template.New("idpSelection").Parse(idpSelectionTemplate)
		if err != nil {
			slog.Error("Failed to parse IdP selection template", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			slog.Error("Failed to execute template", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	idpSelectedHandler := func(w http.ResponseWriter, r *http.Request) {
		// NOTE: sso request is already authenticated by /sso endpoint.

		idpID := r.URL.Path[len("/idp_selected/"):]

		slog.Info("IdP selection",
			slog.String("idp", idpID),
			slog.Any("query", r.URL.Query()),
		)

		// Check if the IDP exists
		provider, ok := providers.Providers[idpID]
		if !ok {
			slog.Info("Invalid IDP ID", slog.String("idp", idpID))
			http.Error(w, "Invalid IDP ID", http.StatusBadRequest)
			return
		}

		slog.Info("IDP found", slog.String("idp", idpID))

		// TODO: Implement to call SAML IdP as a SP using `provider`
	}

	mux.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Processing SAML response from actual IdP")

		// Use the default provider for now
		provider := providers.Default
		if provider != nil && provider.Handler != nil {
			provider.Handler.ServeHTTP(w, r)
		} else {
			http.Error(w, "Default IDP not configured", http.StatusInternalServerError)
		}
	})

	// Create a middleware that logs all requests
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received request", slog.String("path", r.URL.Path))

		switch {
		case strings.HasPrefix(r.URL.Path, "/idp_selected"):
			idpSelectedHandler(w, r)
			return
		case strings.HasPrefix(r.URL.Path, "/idp_select"):
			idpSelectHandler(w, r)
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
func StartServer(config Config, handler http.Handler) error {
	server := &http.Server{
		Addr:              config.Server.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("Starting SAML IdP proxy", slog.String("address", config.Server.ListenAddress))
	slog.Info("Metadata URL (for SPs)", slog.String("url", config.Proxy.MetadataURL))
	slog.Info("SSO URL (for SPs)", slog.String("url", config.Proxy.EntityID+"/sso"))
	slog.Info("ACS URL (for IdPs)", slog.String("url", config.Proxy.AcsURL))
	slog.Info("IdP Selection URL", slog.String("url", config.Proxy.EntityID+"/idp_selected"))

	// Log information about configured IDP
	slog.Info("Configured IDP")
	for _, idp := range config.IDP {
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

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, rv); err != nil {
		panic(err)
	}
	return rv
}
