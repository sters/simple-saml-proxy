package proxy

import (
	"html/template"
	"log/slog"
	"net/http"
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
