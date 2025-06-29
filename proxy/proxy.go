package proxy

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
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

// SetupHTTPHandlers sets up the HTTP handlers for the SAML proxy.
// This proxy acts as a SAML Identity Provider (IdP) proxy:
// - To Service Providers (SPs), it appears as an IdP
// - To Identity Providers (IdPs), it appears as an SP
// It allows users to select which IdP they want to use for authentication.
func SetupHTTPHandlers(idp *IDP, providers *ServiceProviders, config Config) http.Handler {
	// Parse the IdP selection template
	tmpl, err := template.New("idpSelection").Parse(idpSelectionTemplate)
	if err != nil {
		slog.Error("Failed to parse IdP selection template", slog.String("error", err.Error()))
	}
	// Create a custom handler that logs all requests and then delegates to the appropriate handler
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received request", slog.String("path", r.URL.Path))

		// Handle different endpoints
		switch {
		case r.URL.Path == "/metadata":
			idp.Server.IDP.ServeMetadata(w, r)

		case r.URL.Path == "/sso":
			// SSO endpoint - This is where SPs send AuthnRequests
			// The proxy acts as an IdP from the SP's perspective
			samlRequest := r.URL.Query().Get("SAMLRequest")
			if samlRequest == "" {
				http.Error(w, "Missing SAMLRequest parameter", http.StatusBadRequest)
				return
			}

			// TODO: ServeSSOして idp.SessionProvider.GetSession の中でHTMLを返してselect_idpに遷移するほうがいい
			// idp.Server.IDP.ServeSSO()

			// Show IdP selection page
			slog.Info("Showing IdP selection page")
			data := struct {
				Providers map[string]*ServiceProvider
				SelectURL string
			}{
				Providers: providers.Providers,
				SelectURL: "/select_idp",
			}

			err = tmpl.Execute(w, data)
			if err != nil {
				slog.Error("Failed to execute template", slog.String("error", err.Error()))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}

		case strings.HasPrefix(r.URL.Path, "/select_idp/"):
			// IdP selection endpoint - User selects an IdP and is redirected to it
			idpID := r.URL.Path[len("/select_idp/"):]
			query := r.URL.Query()

			slog.Info("IdP selection",
				slog.String("idp", idpID),
				slog.Any("query", query),
			)

			// Check if the IDP exists
			provider, ok := providers.Providers[idpID]
			if !ok {
				slog.Info("Invalid IDP ID", slog.String("idp", idpID))
				http.Error(w, "Invalid IDP ID", http.StatusBadRequest)
				return
			}

			slog.Info("IDP found", slog.String("idp", idpID))

			relayState := base64.RawURLEncoding.EncodeToString(randomBytes(42))
			redirectURL, err := provider.Middleware.ServiceProvider.MakeRedirectAuthenticationRequest(relayState)
			if err != nil {
				slog.Error("Failed to create redirect URL", slog.String("error", err.Error()))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			w.Header().Add("Location", redirectURL.String())
			w.WriteHeader(http.StatusFound)

			slog.Info("Redirecting to IdP", slog.String("url", redirectURL.String()))

		case r.URL.Path == "/saml/acs":
			// ACS endpoint - This is where IdPs send SAML responses
			// The proxy acts as an SP from the IdP's perspective
			provider := providers.Default

			// Process the SAML response from the IdP
			// This is a simplified implementation - in a real-world scenario,
			// you would need to:
			// 1. Parse the SAML response from the IdP
			// 2. Extract the user attributes
			// 3. Create a new SAML response for the SP
			// 4. Sign the response with the proxy's private key
			// 5. Send the response to the SP's ACS URL

			// For now, we'll use a simplified approach:
			// 1. Use the existing ACS handler to process the response from the IdP
			// 2. Redirect the user to the SP with a success message

			slog.Info("Processing SAML response from IdP")

			// NOTE: seems it needs to confiure NotOnOrAfter in Conditions. :thinking:
			// NotOnOrAfter="2025-12-31T19:58:38.464Z"

			// Use the existing ACS handler to process the response
			// TODO: 問題がなかったときにリダイレクトしないでおきたい。プロキシ上でSAMLアサーションを出して、元のSPに戻したい。
			//       wをダミーに置き換えて、もしエラーを返すようなら、そのままwにバイパス、という作りにしないとだめか。
			provider.Middleware.ServeACS(w, r)

			// これをしたいけれどrから読み取ってしまうのでダメかも？
			// idp.Server.IDP.ServeSSO()

			// In a real implementation, we would redirect to the SP's ACS URL with the processed SAML response
			// For now, we'll just log that we processed the response
			slog.Info("Processed SAML response from IdP")

		case r.URL.Path == "/ping":
			// Health check endpoint
			_, err := w.Write([]byte("pong"))
			if err != nil {
				slog.Error("Failed to write response", slog.String("error", err.Error()))
			}

		case r.URL.Path == "/idp-initiated":
			// IdP-Initiated flow endpoint
			// TODO: Implement IdP-Initiated flow
			slog.Info("IdP-Initiated flow not yet implemented")
			http.Error(w, "IdP-Initiated flow not yet implemented", http.StatusNotImplemented)

		default:
			// 404 for any other path
			http.NotFound(w, r)
		}
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
	slog.Info("IdP Selection URL", slog.String("url", config.Proxy.EntityID+"/select_idp"))

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

	if _, err := io.ReadFull(saml.RandReader, rv); err != nil {
		panic(err)
	}
	return rv
}
