package proxy

import (
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
			respondWithInvalidLogout(w, slog.String("operation", "get logout context cookie"))

			return
		}

		// Prepare items for template
		var items []SelectionItem
		for id := range providers.Providers {
			items = append(items, SelectionItem{
				ID:          id,
				Name:        id,
				HiddenField: "idpID",
				Value:       id,
			})
		}

		config := SelectionPageConfig{
			Title:     "Select Identity Provider for Logout",
			Subtitle:  "Please select the identity provider you used to sign in:",
			ActionURL: "/logout_idp_selected",
			ItemClass: "idp-item",
		}

		renderSelectionPage(w, config, items)

		slog.Info("Logout IdP selection page rendered",
			slog.String("logoutContextID", logoutCtxCookie.Value),
		)
	}
}
