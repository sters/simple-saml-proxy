package proxy

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

var errNoIssuer = errors.New("no issuer in SAML request")

// handleSSO wraps the IDP's SSO handler to add SP authorization validation.
func handleSSO(idp *saml.IDP) http.HandlerFunc {
	// Get the original handler
	originalHandler := idp.IDP.HttpHandler()

	return func(w http.ResponseWriter, r *http.Request) {
		// Get SAMLRequest from either query params (GET) or form body (POST)
		var samlRequestParam string
		if r.Method == http.MethodGet {
			samlRequestParam = r.URL.Query().Get("SAMLRequest")
		} else if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				slog.Error("Failed to parse form", slog.String("error", err.Error()))
				http.Error(w, "Bad Request", http.StatusBadRequest)

				return
			}
			samlRequestParam = r.FormValue("SAMLRequest")
		}

		if samlRequestParam == "" {
			// No SAML request, let the original handler deal with it
			originalHandler.ServeHTTP(w, r)

			return
		}

		// Decode and parse the SAML request to get the issuer
		// For POST binding, the request is not deflated
		isPostBinding := r.Method == http.MethodPost
		issuerEntityID, err := extractIssuerFromSAMLRequest(samlRequestParam, isPostBinding)
		if err != nil {
			slog.Error("Failed to extract issuer from SAML request", slog.String("error", err.Error()))
			// Return SAML error response for invalid request
			respondWithSAMLError(w, r, idp, "", "RequestDenied", "Invalid SAML request")

			return
		}

		// Check if the SP is allowed
		storage := idp.GetStorage()
		_, err = storage.GetEntityByID(r.Context(), issuerEntityID)
		if err != nil {
			slog.Warn("Unauthorized SP attempted to access SSO",
				slog.String("entityID", issuerEntityID),
				slog.String("error", err.Error()),
			)

			// Return SAML error response
			respondWithSAMLError(w, r, idp, issuerEntityID, "RequestDenied", "Unauthorized service provider")

			return
		}

		// SP is authorized, continue with normal flow
		originalHandler.ServeHTTP(w, r)
	}
}

// extractIssuerFromSAMLRequest decodes a SAML request and extracts the issuer entity ID.
func extractIssuerFromSAMLRequest(samlRequestParam string, isPostBinding bool) (string, error) {
	var xmlData []byte

	if isPostBinding {
		// For POST binding, the request is base64 encoded but not URL encoded or deflated
		decoded, err := base64.StdEncoding.DecodeString(samlRequestParam)
		if err != nil {
			return "", fmt.Errorf("failed to base64 decode SAML request: %w", err)
		}
		xmlData = decoded
	} else {
		// For GET binding (HTTP-Redirect), the request is base64 encoded and deflated
		// The URL decoding has already been done by r.URL.Query().Get()

		// Base64 decode
		compressed, err := base64.StdEncoding.DecodeString(samlRequestParam)
		if err != nil {
			return "", fmt.Errorf("failed to base64 decode SAML request: %w", err)
		}

		// Decompress using flate
		decompressed, err := decodeDeflatedSAMLRequest(compressed)
		if err != nil {
			// Try without decompression in case it's not compressed
			decompressed = compressed
		}
		xmlData = decompressed
	}

	// Parse as AuthnRequest
	var authnRequest crewjamsaml.AuthnRequest
	if err := xml.Unmarshal(xmlData, &authnRequest); err != nil {
		return "", fmt.Errorf("failed to unmarshal SAML request: %w", err)
	}

	if authnRequest.Issuer == nil {
		return "", errNoIssuer
	}

	return authnRequest.Issuer.Value, nil
}

// decodeDeflatedSAMLRequest decodes a deflated SAML request.
func decodeDeflatedSAMLRequest(compressed []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	var buf bytes.Buffer
	// Limit the amount of data we'll read to prevent decompression bombs
	limited := io.LimitReader(reader, 10*1024*1024) // 10MB limit
	_, err := io.Copy(&buf, limited)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress SAML request: %w", err)
	}

	return buf.Bytes(), nil
}

// respondWithSAMLError sends a SAML error response.
func respondWithSAMLError(w http.ResponseWriter, _ *http.Request, _ *saml.IDP, issuerEntityID, statusCode, statusMessage string) {
	// For simplicity, we'll return an HTML error page since we don't have the ACS URL

	// Create a proper error response
	w.WriteHeader(http.StatusForbidden)
	_, err := io.WriteString(w, `<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .error { color: #d32f2f; }
        .container { max-width: 600px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="error">Access Denied</h1>
        <p>The service provider <strong>`+html.EscapeString(issuerEntityID)+`</strong> is not authorized to use this SAML proxy.</p>
        <p>Status: `+html.EscapeString(statusCode)+`</p>
        <p>Message: `+html.EscapeString(statusMessage)+`</p>
    </div>
</body>
</html>`)
	if err != nil {
		slog.Error("Failed to write error response", slog.String("error", err.Error()))
	}
}
