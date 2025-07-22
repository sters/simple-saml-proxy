package proxy

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

// handleLogoutSPSelected handles the SP selection for IdP-initiated logout and creates the logout request to the SP.
func handleLogoutSPSelected(idp *saml.IDP, _ *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get logout context ID from cookie
		logoutCtxCookie, err := r.Cookie("logout_context_id")
		if err != nil {
			slog.Error("Failed to get logout context cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		// Get logout context from storage
		storage := idp.GetStorage()
		logoutCtx, err := storage.GetLogoutContext(logoutCtxCookie.Value)
		if err != nil {
			slog.Error("Failed to get logout context",
				slog.String("id", logoutCtxCookie.Value),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid logout request", http.StatusBadRequest)

			return
		}

		// Get selected SP
		spEntityID := r.FormValue("spEntityID")
		if spEntityID == "" {
			slog.Error("No SP entity ID provided")
			http.Error(w, "Invalid request", http.StatusBadRequest)

			return
		}

		// Verify the SP is allowed
		_, err = storage.GetEntityByID(r.Context(), spEntityID)
		if err != nil {
			slog.Error("Invalid SP entity ID",
				slog.String("entityID", spEntityID),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid SP", http.StatusBadRequest)

			return
		}

		// Update logout context with target SP
		logoutCtx.TargetID = spEntityID

		// Get the NameID from cookie (stored during IdP-initiated logout)
		nameIDValue := ""
		if nameIDCookie, err := r.Cookie("logout_name_id"); err == nil {
			nameIDValue = nameIDCookie.Value
		}

		slog.Info("SP selected for logout",
			slog.String("sp", spEntityID),
			slog.String("originIdP", logoutCtx.OriginID),
			slog.String("nameID", nameIDValue),
		)

		// Create logout request to the SP
		logoutRequest := &crewjamsaml.LogoutRequest{
			ID:           fmt.Sprintf("id-%x", randomBytes(20)),
			IssueInstant: time.Now(),
			Version:      "2.0",
			Issuer: &crewjamsaml.Issuer{
				Value: idp.IDP.GetEntityID(r.Context()),
			},
			NameID: &crewjamsaml.NameID{
				Value:  nameIDValue,
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
			},
		}

		// Extract SingleLogoutService from SP metadata
		sls, err := storage.GetSingleLogoutServiceFromSP(r.Context(), spEntityID)
		if err != nil {
			slog.Warn("Failed to extract SingleLogoutService from metadata, using fallback",
				slog.String("entityID", spEntityID),
				slog.String("error", err.Error()))
			// Fallback to the previous hardcoded pattern for backward compatibility
			logoutURL := spEntityID + "/logout"
			logoutURLStr, err := buildLogoutURLToSP(logoutRequest, logoutURL, logoutCtx.ID)
			if err != nil {
				slog.Error("Failed to build fallback logout URL", slog.String("error", err.Error()))
				http.Error(w, "Failed to create logout request", http.StatusInternalServerError)

				return
			}
			// Redirect to SP with logout request
			slog.Info("Redirecting to SP for logout (fallback)", slog.String("url", logoutURLStr))
			http.Redirect(w, r, logoutURLStr, http.StatusFound)

			return
		}

		slog.Info("Extracted SingleLogoutService from metadata",
			slog.String("entityID", spEntityID),
			slog.String("binding", sls.Binding),
			slog.String("location", sls.Location))

		// Build the logout URL using the extracted endpoint
		logoutURLStr, err := buildLogoutURLToSP(logoutRequest, sls.Location, logoutCtx.ID)
		if err != nil {
			slog.Error("Failed to build logout URL", slog.String("error", err.Error()))
			http.Error(w, "Failed to create logout request", http.StatusInternalServerError)

			return
		}

		// Store SP ID in cookie for response handling
		SetSecureCookie(w, r, "logout_sp_id", spEntityID, 300)

		// Redirect to SP with logout request
		slog.Info("Redirecting to SP for logout", slog.String("url", logoutURLStr))
		http.Redirect(w, r, logoutURLStr, http.StatusFound)
	}
}

// buildLogoutURLToSP creates the logout URL with encoded SAML request for the SP.
func buildLogoutURLToSP(logoutRequest *crewjamsaml.LogoutRequest, destination string, relayState string) (string, error) {
	// Marshal the logout request
	doc := etree.NewDocument()
	doc.SetRoot(logoutRequest.Element())
	xmlBytes, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("failed to marshal logout request: %w", err)
	}

	// Compress using deflate
	compressed, err := deflateCompress([]byte(xmlBytes))
	if err != nil {
		return "", fmt.Errorf("failed to compress logout request: %w", err)
	}

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(compressed)

	// Build URL
	logoutURL, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("failed to parse destination URL: %w", err)
	}

	query := logoutURL.Query()
	query.Set("SAMLRequest", encoded)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	logoutURL.RawQuery = query.Encode()

	return logoutURL.String(), nil
}
