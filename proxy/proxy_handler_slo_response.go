package proxy

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

var (
	errResponseIssueInstantInFuture = errors.New("logout response issue instant is in the future")
	errResponseTooOld               = errors.New("logout response is too old")
)

// handleSLOResponse handles logout responses from SPs in the IdP-initiated flow.
// This completes the IdP-initiated logout by sending a response back to the originating IdP.
func handleSLOResponse(idp *saml.IDP, _ *saml.ServiceProviders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received logout response from SP",
			slog.String("method", r.Method),
			slog.String("url", r.URL.String()),
		)

		// Get the SAMLResponse parameter
		samlResponseParam := r.URL.Query().Get("SAMLResponse")
		if samlResponseParam == "" {
			slog.Error("No SAMLResponse parameter in logout response")
			http.Error(w, "Missing SAMLResponse parameter", http.StatusBadRequest)

			return
		}

		// Parse the logout response from SP
		logoutResponse, err := parseLogoutResponse(samlResponseParam)
		if err != nil {
			slog.Error("Failed to parse SP logout response", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout response", http.StatusBadRequest)

			return
		}

		// Validate response issue instant
		if err := validateResponseIssueInstant(logoutResponse.IssueInstant); err != nil {
			slog.Error("SP logout response failed time validation",
				slog.String("error", err.Error()),
			)
			http.Error(w, "Invalid logout response", http.StatusBadRequest)

			return
		}

		// Get logout context from cookie
		logoutCtxCookie, err := r.Cookie("logout_context_id")
		if err != nil {
			slog.Error("Failed to get logout context cookie", slog.String("error", err.Error()))
			http.Error(w, "Invalid logout response", http.StatusBadRequest)

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
			http.Error(w, "Invalid logout response", http.StatusBadRequest)

			return
		}

		slog.Info("Parsed SP logout response",
			slog.String("status", getLogoutResponseStatus(logoutResponse)),
			slog.String("originIdP", logoutCtx.OriginID),
			slog.String("targetSP", logoutCtx.TargetID),
		)

		// Create logout response to send back to the originating IdP
		finalResponse := &crewjamsaml.LogoutResponse{
			ID:           fmt.Sprintf("id-%x", randomBytes(20)),
			InResponseTo: "", // Would be set if we tracked the original request ID
			Version:      "2.0",
			IssueInstant: logoutResponse.IssueInstant,
			Issuer: &crewjamsaml.Issuer{
				Value: idp.IDP.GetEntityID(r.Context()),
			},
			Status: logoutResponse.Status, // Pass through the status from SP
		}

		// For IdP-initiated flow, we need to send response back to the originating IdP
		// The response URL should be in the IdP's metadata
		// For now, we'll use a standard pattern
		idpResponseURL := logoutCtx.OriginID + "/slo/response"

		// Build the logout response URL
		responseURL, err := buildLogoutResponseURL(finalResponse, idpResponseURL, logoutCtx.RelayState)
		if err != nil {
			slog.Error("Failed to build logout response URL", slog.String("error", err.Error()))
			http.Error(w, "Failed to create logout response", http.StatusInternalServerError)

			return
		}

		// Clean up the logout context
		storage.DeleteLogoutContext(logoutCtx.ID)

		// Clear cookies
		http.SetCookie(w, &http.Cookie{
			Name:   "logout_context_id",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.SetCookie(w, &http.Cookie{
			Name:   "logout_sp_id",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.SetCookie(w, &http.Cookie{
			Name:   "logout_name_id",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		// Redirect to IdP with logout response
		slog.Info("Redirecting to IdP with logout response", slog.String("url", responseURL))
		http.Redirect(w, r, responseURL, http.StatusFound)
	}
}

// getLogoutResponseStatus extracts the status code from a logout response.
func getLogoutResponseStatus(resp *crewjamsaml.LogoutResponse) string {
	if resp.Status.StatusCode.Value != "" {
		return resp.Status.StatusCode.Value
	}

	return "unknown"
}

// parseLogoutResponse parses a SAML logout response.
func parseLogoutResponse(samlResponseParam string) (*crewjamsaml.LogoutResponse, error) {
	// Base64 decode (the samlResponseParam should already be URL-decoded by Go's query parsing)
	compressed, err := base64.StdEncoding.DecodeString(samlResponseParam)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode logout response: %w", err)
	}

	// Try to decompress
	decompressed, err := decodeDeflatedData(compressed)
	if err != nil {
		// Try without decompression
		decompressed = compressed
	}

	// Parse as LogoutResponse
	var logoutResponse crewjamsaml.LogoutResponse
	if err := xml.Unmarshal(decompressed, &logoutResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal logout response: %w", err)
	}

	return &logoutResponse, nil
}

// decodeDeflatedData decodes deflated data.
func decodeDeflatedData(compressed []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	var buf bytes.Buffer
	limited := io.LimitReader(reader, 10*1024*1024) // 10MB limit
	_, err := io.Copy(&buf, limited)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	return buf.Bytes(), nil
}

// buildLogoutResponseURL creates the logout response URL with encoded SAML response.
func buildLogoutResponseURL(logoutResponse *crewjamsaml.LogoutResponse, destination string, relayState string) (string, error) {
	// Marshal the logout response
	doc := etree.NewDocument()
	doc.SetRoot(logoutResponse.Element())
	xmlBytes, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("failed to marshal logout response: %w", err)
	}

	// Compress using deflate
	compressed, err := deflateCompress([]byte(xmlBytes))
	if err != nil {
		return "", fmt.Errorf("failed to compress logout response: %w", err)
	}

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(compressed)

	// Build URL
	responseURL, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("failed to parse destination URL: %w", err)
	}

	query := responseURL.Query()
	query.Set("SAMLResponse", encoded)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	responseURL.RawQuery = query.Encode()

	return responseURL.String(), nil
}

// validateResponseIssueInstant checks if the logout response was issued recently.
func validateResponseIssueInstant(issueInstant time.Time) error {
	const maxAge = 5 * time.Minute

	now := time.Now()
	age := now.Sub(issueInstant)

	if age < 0 {
		// Issue instant is in the future
		return fmt.Errorf("%w: %v", errResponseIssueInstantInFuture, issueInstant)
	}

	if age > maxAge {
		return fmt.Errorf("%w: issued %v ago", errResponseTooOld, age)
	}

	return nil
}
