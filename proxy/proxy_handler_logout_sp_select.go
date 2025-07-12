package proxy

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// handleLogoutSPSelect displays the SP selection page for IdP-initiated logout.
func handleLogoutSPSelect(idp *saml.IDP, _ *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Displaying logout SP selection page")

		// Get logout context ID from cookie
		logoutCtxCookie, err := r.Cookie("logout_context_id")
		if err != nil {
			slog.Error("Failed to get logout context cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		// Get the configured allowed SPs
		storage := idp.GetStorage()
		allowedSPs := storage.GetAllowedSPs()

		// Prepare data for template
		type templateData struct {
			SPs []struct {
				EntityID string
				Name     string
			}
		}

		data := templateData{}
		for _, sp := range allowedSPs {
			data.SPs = append(data.SPs, struct {
				EntityID string
				Name     string
			}{
				EntityID: sp.EntityID,
				Name:     sp.EntityID, // Could be enhanced with display names
			})
		}

		// HTML template for SP selection
		tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>Select Service Provider for Logout</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #333; }
        .sp-list { list-style: none; padding: 0; }
        .sp-item { 
            margin: 10px 0; 
            padding: 15px; 
            background: #f5f5f5; 
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .sp-item:hover { background: #e0e0e0; }
        form { margin: 0; }
        button {
            background: none;
            border: none;
            width: 100%;
            text-align: left;
            font-size: 16px;
            cursor: pointer;
            color: #333;
        }
        .note {
            margin-top: 20px;
            padding: 15px;
            background: #fff3cd;
            border: 1px solid #ffeeba;
            border-radius: 5px;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Select Service Provider for Logout</h1>
        <p>Your identity provider has initiated a logout. Please select which service provider you want to log out from:</p>
        <ul class="sp-list">
            {{range .SPs}}
            <li class="sp-item">
                <form method="POST" action="/logout_sp_selected">
                    <input type="hidden" name="spEntityID" value="{{.EntityID}}">
                    <button type="submit">{{.Name}}</button>
                </form>
            </li>
            {{end}}
        </ul>
        <div class="note">
            <strong>Note:</strong> You will only be logged out from the selected service provider. 
            To log out from other services, you may need to repeat this process or log out from each service individually.
        </div>
    </div>
</body>
</html>`

		// Parse and execute template
		t, err := template.New("logout_sp_select").Parse(tmpl)
		if err != nil {
			slog.Error("Failed to parse template", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := t.Execute(w, data); err != nil {
			slog.Error("Failed to execute template", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}

		slog.Info("Logout SP selection page rendered",
			slog.String("logoutContextID", logoutCtxCookie.Value),
			slog.Int("spCount", len(data.SPs)),
		)
	}
}
