package proxy

import (
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
			respondWithInvalidLogout(w, slog.String("operation", "get logout context cookie"))

			return
		}

		// Get the configured allowed SPs
		storage := idp.GetStorage()
		allowedSPs := storage.GetAllowedSPs()

		// Prepare items for template
		var items []SelectionItem
		for _, sp := range allowedSPs {
			items = append(items, SelectionItem{
				ID:          sp.EntityID,
				Name:        sp.EntityID,
				HiddenField: "spEntityID",
				Value:       sp.EntityID,
			})
		}

		config := SelectionPageConfig{
			Title:     "Select Service Provider for Logout",
			Subtitle:  "Your identity provider has initiated a logout. Please select which service provider you want to log out from:",
			ActionURL: "/logout_sp_selected",
			ItemClass: "sp-item",
			Note:      "You will only be logged out from the selected service provider. To log out from other services, you may need to repeat this process or log out from each service individually.",
		}

		renderSelectionPage(w, config, items)

		slog.Info("Logout SP selection page rendered",
			slog.String("logoutContextID", logoutCtxCookie.Value),
			slog.Int("spCount", len(items)),
		)
	}
}
