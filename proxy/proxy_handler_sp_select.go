package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/sters/simple-saml-proxy/config"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// generateRandomID generates a random hex string ID
func generateRandomID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// handleSPSelect shows the SP selection page for IdP-initiated flow
func handleSPSelect(idp *saml.IDP, providers *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Showing SP selection page for IdP-initiated flow")

		// Get the session cookie
		sessionCookie, err := r.Cookie("idp_initiated_session")
		if err != nil {
			slog.Error("Failed to get session cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}

		sessionID := sessionCookie.Value
		if sessionID == "" {
			slog.Error("Session ID is empty")
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}

		// Get allowed SPs
		storage := idp.GetStorage()
		allowedSPs := storage.GetAllowedSPs()
		if len(allowedSPs) == 0 {
			slog.Error("No allowed SPs configured")
			http.Error(w, "No service providers available", http.StatusInternalServerError)
			return
		}

		// Create SP selection HTML
		tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>Select Service Provider</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }
        .container {
            background-color: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        h1 {
            color: #333;
            margin-bottom: 1.5rem;
        }
        .sp-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .sp-button {
            display: block;
            width: 100%;
            padding: 1rem;
            margin: 0.5rem 0;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }
        .sp-button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Select Service Provider</h1>
        <p>You have been authenticated. Please select the service you want to access:</p>
        <div class="sp-list">
            {{range .SPs}}
            <form method="post" action="/sp_selected">
                <input type="hidden" name="sp_entity_id" value="{{.EntityID}}" />
                <input type="hidden" name="session_id" value="{{$.SessionID}}" />
                <button type="submit" class="sp-button">{{.EntityID}}</button>
            </form>
            {{end}}
        </div>
    </div>
</body>
</html>
`

		t, err := template.New("sp_select").Parse(tmpl)
		if err != nil {
			slog.Error("Failed to parse template", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		data := struct {
			SPs       []config.SPConfig
			SessionID string
		}{
			SPs:       allowedSPs,
			SessionID: sessionID,
		}

		w.Header().Set("Content-Type", "text/html")
		if err := t.Execute(w, data); err != nil {
			slog.Error("Failed to execute template", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
}

// handleSPSelected handles the SP selection for IdP-initiated flow
func handleSPSelected(idp *saml.IDP, providers *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			slog.Error("Failed to parse form", slog.String("error", err.Error()))
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		sessionID := r.FormValue("session_id")
		spEntityID := r.FormValue("sp_entity_id")

		if sessionID == "" || spEntityID == "" {
			slog.Error("Missing required parameters")
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Get the auth request from storage
		authRequest, err := idp.IDPStorage.AuthRequestByID(r.Context(), sessionID)
		if err != nil {
			slog.Error("Failed to get auth request", slog.String("error", err.Error()))
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}

		ar, ok := authRequest.(*saml.AuthRequest)
		if !ok || ar.Assertion == nil {
			slog.Error("Invalid auth request or missing assertion")
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}

		// Find the selected SP
		storage := idp.GetStorage()
		allowedSPs := storage.GetAllowedSPs()
		var selectedSP *config.SPConfig
		for _, sp := range allowedSPs {
			if sp.EntityID == spEntityID {
				selectedSP = &sp
				break
			}
		}

		if selectedSP == nil {
			slog.Error("Invalid SP selected", slog.String("entity_id", spEntityID))
			http.Error(w, "Invalid service provider", http.StatusBadRequest)
			return
		}

		slog.Info("SP selected for IdP-initiated flow",
			slog.String("sp_entity_id", spEntityID),
			slog.String("session_id", sessionID))

		// Clear the session cookies
		http.SetCookie(w, &http.Cookie{
			Name:     "idp_initiated_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "idp_initiated_provider",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
		})

		// Redirect to SP with assertion
		redirectToSPWithAssertion(w, r, idp, *selectedSP, ar.Assertion, sessionID)
	}
}