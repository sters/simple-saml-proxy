package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// idpSelectionTemplate is the HTML template for the IdP selection page.
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
		const onClick = (idpID) => {
			const url = new URL("{{$.SelectURL}}", location.origin);
			url.searchParams.append("idpID", idpID);
			{{if $.RelayState}}url.searchParams.append("RelayState", "{{$.RelayState}}");{{end}}
			window.location.href = url.toString();
			return false;
		};
	</script>
</head>
<body>
    <h1>Select an Identity Provider</h1>
    {{if $.RelayState}}<input type="hidden" id="RelayState" value="{{$.RelayState}}">{{end}}
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

const (
	cookieNameAuthRequestID = "authID"
	cookieNameIDPID         = "idpID"
	relayStateLength        = 42
)

// handlePing handles the /ping health check endpoint.
func handlePing(w http.ResponseWriter, _ *http.Request) {
	// Health check endpoint
	_, err := w.Write([]byte("pong"))
	if err != nil {
		slog.Error("Failed to write response", slog.String("error", err.Error()))
	}
}

// isSecureCookie determines if cookies should be secure based on the request.
func isSecureCookie(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// handleIDPSelect handles the IdP selection page.
func handleIDPSelect(idp *IDP, providers *ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authRequestID := r.FormValue("id")
		if authRequestID == "" {
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		authRequest, err := idp.idpStorage.AuthRequestByID(r.Context(), authRequestID)
		if err != nil {
			slog.Error("Failed to get auth request",
				slog.String("id", authRequestID),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid request", http.StatusInternalServerError)

			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieNameAuthRequestID,
			Value:    authRequestID,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecureCookie(r),
		})

		relayState := ""
		if ar, ok := authRequest.(*AuthRequest); ok {
			relayState = ar.RelayState
		}

		data := struct {
			Providers  map[string]*ServiceProvider
			SelectURL  string
			RelayState string
		}{
			Providers:  providers.Providers,
			SelectURL:  "/idp_selected",
			RelayState: relayState,
		}

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
}

// handleIDPSelected handles the IdP selection result and redirects to the selected IdP.
func handleIDPSelected(idp *IDP, providers *ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authRequestIDCookie, err := r.Cookie(cookieNameAuthRequestID)
		if err != nil {
			slog.Error("Failed to get auth request ID cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		authRequestID := authRequestIDCookie.Value
		if authRequestID == "" {
			slog.Error("Auth request ID cookie is empty")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		authRequest, err := idp.idpStorage.AuthRequestByID(r.Context(), authRequestID)
		if err != nil {
			slog.Error("Failed to get auth request",
				slog.String("id", authRequestID),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid request", http.StatusInternalServerError)

			return
		}

		idpID := r.FormValue("idpID")
		slog.Info("IdP selection",
			slog.String("idp", idpID),
			slog.Any("query", r.URL.Query()),
		)

		provider, ok := providers.Providers[idpID]
		if !ok {
			slog.Info("Invalid IDP ID", slog.String("idp", idpID))
			http.Error(w, "Invalid IDP ID", http.StatusBadRequest)

			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieNameIDPID,
			Value:    idpID,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecureCookie(r),
		})

		slog.Info("IDP found", slog.String("idp", idpID))

		// Use original relay state from auth request if available
		var relayState string
		if ar, ok := authRequest.(*AuthRequest); ok && ar.RelayState != "" {
			relayState = ar.RelayState
		} else {
			relayState = base64.RawURLEncoding.EncodeToString(randomBytes(relayStateLength))
		}
		redirectURL, err := provider.Middleware.ServiceProvider.MakeRedirectAuthenticationRequest(relayState)
		if err != nil {
			slog.Error("Failed to create redirect URL", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}

		w.Header().Add("Location", redirectURL.String())
		w.WriteHeader(http.StatusFound)

		slog.Info("Redirecting to IdP", slog.String("url", redirectURL.String()))
	}
}

// handleSAMLACS handles the SAML assertion consumer service endpoint.
func handleSAMLACS(idp *IDP, providers *ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Processing SAML response from actual IdP")

		authRequestIDCookie, err := r.Cookie(cookieNameAuthRequestID)
		if err != nil {
			slog.Error("Failed to get auth request ID cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		authRequestID := authRequestIDCookie.Value
		if authRequestID == "" {
			slog.Error("Auth request ID cookie is empty")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		authRequest, err := idp.idpStorage.AuthRequestByID(r.Context(), authRequestID)
		if err != nil {
			slog.Error("Failed to get auth request",
				slog.String("id", authRequestID),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid request", http.StatusInternalServerError)

			return
		}

		if ar, ok := authRequest.(*AuthRequest); ok {
			ar.IsDone = true // 自分でDone=trueにしないといけない
		} else {
			slog.Error("Failed to cast authRequest to *AuthRequest")
			http.Error(w, "Invalid request", http.StatusInternalServerError)

			return
		}

		idpIDCookie, err := r.Cookie(cookieNameIDPID)
		if err != nil {
			slog.Error("Failed to get IDP ID cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		idpID := idpIDCookie.Value
		if idpID == "" {
			slog.Error("IDP ID cookie is empty")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		provider, ok := providers.Providers[idpID]
		if !ok {
			slog.Error("Invalid IDP ID", slog.String("idp", idpID))
			http.Error(w, "Invalid IDP ID", http.StatusBadRequest)

			return
		}

		if err := r.ParseForm(); err != nil {
			slog.Error("Failed to parse form", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		trackedRequests := provider.Middleware.RequestTracker.GetTrackedRequests(r)
		possibleRequestIDs := make([]string, len(trackedRequests))
		for i, tr := range trackedRequests {
			possibleRequestIDs[i] = tr.SAMLRequestID
		}

		assertion, err := provider.Middleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
		if err != nil {
			slog.Error("Failed to parse response", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		slog.Info(
			"Assertion",
			slog.Any("subject", assertion.Subject),
			slog.Any("attributes", assertion.AttributeStatements),
		)

		if assertion.Subject == nil || assertion.Subject.NameID == nil {
			slog.Error("Assertion does not contain NameID")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		callbackURL := idp.idp.AuthCallbackURL()(r.Context(), authRequestID)
		http.Redirect(w, r, callbackURL, http.StatusFound)
	}
}

// handleIDPInitiated handles the IdP-initiated flow endpoint.
func handleIDPInitiated(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "IdP-Initiated flow not yet implemented", http.StatusNotImplemented)
}

// SetupHTTPHandlers sets up the HTTP handlers for the SAML proxy.
// This proxy acts as a SAML Identity Provider (IdP) proxy:
// - To Service Providers (SPs), it appears as an IdP
// - To Identity Providers (IdPs), it appears as an SP
// It allows users to select which IdP they want to use for authentication.
func SetupHTTPHandlers(idp *IDP, providers *ServiceProviders, _ Config) http.Handler {
	mux := http.NewServeMux()

	// Basic endpoints
	mux.HandleFunc("/ping", handlePing)
	mux.Handle("/metadata", idp.idp.HttpHandler())
	mux.Handle("/sso", idp.idp.HttpHandler())
	mux.Handle("/callback", idp.idp.HttpHandler())

	// SAML proxy endpoints
	mux.HandleFunc("/saml/acs", handleSAMLACS(idp, providers))
	mux.HandleFunc("/idp-initiated", handleIDPInitiated)

	// Create request handler with routing
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received request", slog.String("path", r.URL.Path))

		switch {
		case strings.HasPrefix(r.URL.Path, "/idp_selected"):
			handleIDPSelected(idp, providers)(w, r)

			return
		case strings.HasPrefix(r.URL.Path, "/idp_select"):
			handleIDPSelect(idp, providers)(w, r)

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
		return nil
	}

	return rv
}
