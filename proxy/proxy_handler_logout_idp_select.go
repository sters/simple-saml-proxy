package proxy

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// handleLogoutIDPSelect displays the IdP selection page for logout.
func handleLogoutIDPSelect(_ *saml.IDP, providers *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Displaying logout IdP selection page")

		// Get logout context ID from cookie
		logoutCtxCookie, err := r.Cookie("logout_context_id")
		if err != nil {
			slog.Error("Failed to get logout context cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		// Prepare data for template
		type templateData struct {
			IDPs []struct {
				ID   string
				Name string
			}
		}

		data := templateData{}
		for id := range providers.Providers {
			data.IDPs = append(data.IDPs, struct {
				ID   string
				Name string
			}{
				ID:   id,
				Name: id, // Could be enhanced with display names
			})
		}

		// HTML template for IdP selection
		tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>Select Identity Provider for Logout</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #333; }
        .idp-list { list-style: none; padding: 0; }
        .idp-item { 
            margin: 10px 0; 
            padding: 15px; 
            background: #f5f5f5; 
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .idp-item:hover { background: #e0e0e0; }
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
    </style>
</head>
<body>
    <div class="container">
        <h1>Select Identity Provider for Logout</h1>
        <p>Please select the identity provider you used to sign in:</p>
        <ul class="idp-list">
            {{range .IDPs}}
            <li class="idp-item">
                <form method="POST" action="/logout_idp_selected">
                    <input type="hidden" name="idpID" value="{{.ID}}">
                    <button type="submit">{{.Name}}</button>
                </form>
            </li>
            {{end}}
        </ul>
    </div>
</body>
</html>`

		// Parse and execute template
		t, err := template.New("logout_idp_select").Parse(tmpl)
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

		slog.Info("Logout IdP selection page rendered",
			slog.String("logoutContextID", logoutCtxCookie.Value),
		)
	}
}
