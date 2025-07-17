package proxy

import (
	"html/template"
	"log/slog"
	"net/http"
)

// SelectionPageConfig holds configuration for selection page templates.
type SelectionPageConfig struct {
	Title       string
	Subtitle    string
	ActionURL   string
	ButtonClass string
	ItemClass   string
	Note        string
}

// SelectionPageData holds data for selection page templates.
type SelectionPageData struct {
	Config SelectionPageConfig
	Items  []SelectionItem
}

// SelectionItem represents an item in a selection list.
type SelectionItem struct {
	ID          string
	Name        string
	HiddenField string
	Value       string
}

// selectionPageTemplate is the shared HTML template for selection pages.
const selectionPageTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>{{.Config.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #333; }
        .item-list { list-style: none; padding: 0; }
        .{{.Config.ItemClass}} { 
            margin: 10px 0; 
            padding: 15px; 
            background: #f5f5f5; 
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .{{.Config.ItemClass}}:hover { background: #e0e0e0; }
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
        <h1>{{.Config.Title}}</h1>
        {{if .Config.Subtitle}}<p>{{.Config.Subtitle}}</p>{{end}}
        <ul class="item-list">
            {{range .Items}}
            <li class="{{$.Config.ItemClass}}">
                <form method="POST" action="{{$.Config.ActionURL}}">
                    <input type="hidden" name="{{.HiddenField}}" value="{{.Value}}">
                    <button type="submit">{{.Name}}</button>
                </form>
            </li>
            {{end}}
        </ul>
        {{if .Config.Note}}
        <div class="note">
            <strong>Note:</strong> {{.Config.Note}}
        </div>
        {{end}}
    </div>
</body>
</html>`

// renderSelectionPage renders a selection page with the given configuration and data.
func renderSelectionPage(w http.ResponseWriter, config SelectionPageConfig, items []SelectionItem) {
	data := SelectionPageData{
		Config: config,
		Items:  items,
	}

	tmpl, err := template.New("selection").Parse(selectionPageTemplate)
	if err != nil {
		slog.Error("Failed to parse selection template", slog.String("error", err.Error()))
		http.Error(w, "Internal server error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		slog.Error("Failed to execute selection template", slog.String("error", err.Error()))
		http.Error(w, "Internal server error", http.StatusInternalServerError)

		return
	}
}
