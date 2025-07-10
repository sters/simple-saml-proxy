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

	crewjamsaml "github.com/crewjam/saml"
	"github.com/sters/simple-saml-proxy/proxy/saml"
)

var errNoIssuer = errors.New("no issuer in SAML request")

// handleSSO wraps the IDP's SSO handler to add SP authorization validation.
func handleSSO(idp *saml.IDP) http.HandlerFunc {
	// Get the original handler
	originalHandler := idp.IDP.HttpHandler()

	return func(w http.ResponseWriter, r *http.Request) {
		// Only validate for SAML requests
		samlRequestParam := r.URL.Query().Get("SAMLRequest")
		if samlRequestParam == "" {
			// No SAML request, let the original handler deal with it
			originalHandler.ServeHTTP(w, r)

			return
		}

		// Decode and parse the SAML request to get the issuer
		issuerEntityID, err := extractIssuerFromSAMLRequest(samlRequestParam)
		if err != nil {
			slog.Error("Failed to extract issuer from SAML request", slog.String("error", err.Error()))
			// Let the original handler deal with the error
			originalHandler.ServeHTTP(w, r)

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
func extractIssuerFromSAMLRequest(samlRequestParam string) (string, error) {
	// URL decode
	decoded, err := url.QueryUnescape(samlRequestParam)
	if err != nil {
		return "", fmt.Errorf("failed to URL decode SAML request: %w", err)
	}

	// Base64 decode
	compressed, err := base64.StdEncoding.DecodeString(decoded)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode SAML request: %w", err)
	}

	// Decompress using flate
	decompressed, err := decodeDeflatedSAMLRequest(compressed)
	if err != nil {
		// Try without decompression in case it's not compressed
		decompressed = compressed
	}

	// Parse as AuthnRequest
	var authnRequest crewjamsaml.AuthnRequest
	if err := xml.Unmarshal(decompressed, &authnRequest); err != nil {
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
        <p>The service provider <strong>`+issuerEntityID+`</strong> is not authorized to use this SAML proxy.</p>
        <p>Status: `+statusCode+`</p>
        <p>Message: `+statusMessage+`</p>
    </div>
</body>
</html>`)
	if err != nil {
		slog.Error("Failed to write error response", slog.String("error", err.Error()))
	}
}
