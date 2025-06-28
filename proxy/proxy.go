package proxy

import (
	"fmt"
	"html/template"
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
</head>
<body>
    <h1>Select an Identity Provider</h1>
    <div class="idp-list">
        {{range .Providers}}
        <a href="{{$.SelectURL}}/{{.ID}}?SAMLRequest={{$.SAMLRequest}}&RelayState={{$.RelayState}}" class="idp-button">
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
// TODO: Support IdP-Initiated flow
func SetupHTTPHandlers(providers *SAMLServiceProviders, config Config) http.Handler {
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
			// Metadata endpoint - This endpoint now serves metadata for SPs
			// The proxy acts as an IdP from the SP's perspective
			// TODO: Implement IdP metadata generation
			slog.Info("Serving IdP metadata to SP")
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte("<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + config.Proxy.EntityID + "\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"></IDPSSODescriptor></EntityDescriptor>"))

		case r.URL.Path == "/sso":
			// SSO endpoint - This is where SPs send AuthnRequests
			// The proxy acts as an IdP from the SP's perspective
			samlRequest := r.URL.Query().Get("SAMLRequest")
			relayState := r.URL.Query().Get("RelayState")

			if samlRequest == "" {
				http.Error(w, "Missing SAMLRequest parameter", http.StatusBadRequest)
				return
			}

			// Show IdP selection page
			slog.Info("Showing IdP selection page")
			data := struct {
				Providers   map[string]*IDPServiceProvider
				SelectURL   string
				SAMLRequest string
				RelayState  string
			}{
				Providers:   providers.Providers,
				SelectURL:   "/select_idp",
				SAMLRequest: samlRequest,
				RelayState:  relayState,
			}

			err = tmpl.Execute(w, data)
			if err != nil {
				slog.Error("Failed to execute template", slog.String("error", err.Error()))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}

		case strings.HasPrefix(r.URL.Path, "/select_idp/"):
			// IdP selection endpoint - User selects an IdP and is redirected to it
			idpID := r.URL.Path[len("/select_idp/"):]
			samlRequest := r.URL.Query().Get("SAMLRequest")
			relayState := r.URL.Query().Get("RelayState")

			slog.Info("IdP selection",
				slog.String("idp", idpID),
				slog.String("samlRequest", samlRequest),
				slog.String("relayState", relayState))

			// Check if the IDP exists
			if provider, ok := providers.Providers[idpID]; ok {
				slog.Info("IDP found", slog.String("idp", idpID))

				// Set the cookie with the IDP ID
				cookie := &http.Cookie{
					Name:     config.Proxy.CookieName,
					Value:    idpID,
					Path:     "/",
					HttpOnly: true,
					Secure:   r.TLS != nil,
					SameSite: http.SameSiteLaxMode,
				}
				http.SetCookie(w, cookie)
				slog.Info("Set cookie", slog.String("name", cookie.Name), slog.String("value", cookie.Value))

				// Forward the SAML request to the selected IdP
				// Build the redirect URL to the IdP's SSO URL with the SAML request and relay state
				redirectURL := provider.Middleware.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding)
				redirectURL += "?SAMLRequest=" + samlRequest
				if relayState != "" {
					redirectURL += "&RelayState=" + relayState
				}

				slog.Info("Redirecting to IdP", slog.String("url", redirectURL))
				http.Redirect(w, r, redirectURL, http.StatusFound)
			} else {
				slog.Info("Invalid IDP ID", slog.String("idp", idpID))
				http.Error(w, "Invalid IDP ID", http.StatusBadRequest)
			}

		case r.URL.Path == "/sso/acs":
			// ACS endpoint - This is where IdPs send SAML responses
			// The proxy acts as an SP from the IdP's perspective
			cookie, err := r.Cookie(config.Proxy.CookieName)
			var idpID string
			if err == nil {
				idpID = cookie.Value
			}
			provider := providers.GetProvider(idpID)

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

			// TODO: Implement full SAML response processing and forwarding
			slog.Info("Processing SAML response from IdP", slog.String("idp", idpID))

			// Get the relay state, which should contain the SP's ACS URL
			relayState := r.URL.Query().Get("RelayState")
			if relayState == "" {
				relayState = r.FormValue("RelayState")
			}

			// Use the existing ACS handler to process the response
			provider.Middleware.ServeACS(w, r)

			// In a real implementation, we would redirect to the SP's ACS URL with the processed SAML response
			// For now, we'll just log that we processed the response
			slog.Info("Processed SAML response from IdP",
				slog.String("idp", idpID),
				slog.String("relayState", relayState))

		case strings.HasPrefix(r.URL.Path, "/link_sso/"):
			// Legacy Link SSO endpoint for IDP selection
			// This is kept for backward compatibility
			idpID := r.URL.Path[len("/link_sso/"):]
			slog.Info("Legacy Link SSO request", slog.String("idp", idpID))

			// Check if the IDP exists
			if _, ok := providers.Providers[idpID]; ok {
				slog.Info("IDP found", slog.String("idp", idpID))

				// Set the cookie with the IDP ID
				cookie := &http.Cookie{
					Name:     config.Proxy.CookieName,
					Value:    idpID,
					Path:     "/",
					HttpOnly: true,
					Secure:   r.TLS != nil,
					SameSite: http.SameSiteLaxMode,
				}
				http.SetCookie(w, cookie)
				slog.Info("Set cookie", slog.String("name", cookie.Name), slog.String("value", cookie.Value))

				// Get the service URL from the query parameter
				serviceURL := r.URL.Query().Get("service")
				if serviceURL == "" {
					serviceURL = "/"
				}
				slog.Info("Service URL", slog.String("url", serviceURL))

				// Validate the service URL against allowed prefixes
				if !isAllowedServiceURL(serviceURL, config.Proxy.AllowedServiceURLPrefix) {
					slog.Info("Invalid service URL", slog.String("url", serviceURL))
					http.Error(w, "Invalid service URL", http.StatusBadRequest)
					return
				}

				// Redirect to the service URL
				slog.Info("Redirecting", slog.String("url", serviceURL))
				w.Header().Set("Location", serviceURL)
				w.WriteHeader(http.StatusFound)
				slog.Info("Redirect sent", slog.Int("status", http.StatusFound))
			} else {
				slog.Info("Invalid IDP ID", slog.String("idp", idpID))
				http.Error(w, "Invalid IDP ID", http.StatusBadRequest)
			}

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
			slog.String("entityID", idp.EntityID),
			slog.String("id", idp.ID),
			slog.String("ssoURL", idp.SSOURL),
			slog.String("linkSSOURL", config.Proxy.EntityID+"/link_sso/"+idp.ID))
	}

	err := server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}
