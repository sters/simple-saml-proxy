package proxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
)

// samlResponseInterceptor intercepts SAML responses and fixes the Version attribute
type samlResponseInterceptor struct {
	handler http.Handler
}

func newSAMLResponseInterceptor(handler http.Handler) http.Handler {
	return &samlResponseInterceptor{handler: handler}
}

func (s *samlResponseInterceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("id")
	slog.Info("SAML Response Interceptor called", 
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("id", requestID),
		slog.String("user-agent", r.Header.Get("User-Agent")))

	// Only intercept GET requests with id parameter (these generate SAML response forms)
	if r.Method != http.MethodGet {
		slog.Info("Not a GET request, passing through", slog.String("method", r.Method))
		s.handler.ServeHTTP(w, r)
		return
	}

	// Check if this is a callback with id parameter
	if requestID == "" {
		slog.Info("No id parameter found, passing through")
		s.handler.ServeHTTP(w, r)
		return
	}

	slog.Info("Intercepting callback request", slog.String("id", requestID))

	// Capture the response
	recorder := &responseRecorder{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}

	s.handler.ServeHTTP(recorder, r)

	// Log the response details
	body := recorder.body.String()
	slog.Info("Captured response", 
		slog.Int("status", recorder.statusCode),
		slog.Int("body_length", len(body)),
		slog.Bool("contains_saml_response", strings.Contains(body, "SAMLResponse")),
		slog.Bool("contains_form", strings.Contains(body, "<form")))

	// Check if this is an HTML form with SAMLResponse
	if !strings.Contains(body, "SAMLResponse") || !strings.Contains(body, "<form") {
		slog.Info("Not a SAML response form, writing original response")
		// Not a SAML response form, write original response
		w.WriteHeader(recorder.statusCode)
		w.Write(recorder.body.Bytes())
		return
	}

	slog.Info("Processing SAML response form for Version attribute fix")

	// Extract and fix the SAMLResponse
	fixedBody, err := fixSAMLResponse(body)
	if err != nil {
		slog.Error("Failed to fix SAML response", slog.String("error", err.Error()))
		// Write original response on error
		w.WriteHeader(recorder.statusCode)
		w.Write(recorder.body.Bytes())
		return
	}

	slog.Info("Successfully fixed SAML response")

	// Write the fixed response
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(recorder.statusCode)
	w.Write([]byte(fixedBody))
}

func fixSAMLResponse(htmlBody string) (string, error) {
	slog.Info("Starting SAML response fix", slog.Int("html_length", len(htmlBody)))
	slog.Info("HTML body snippet", slog.String("html_snippet", htmlBody[:min(500, len(htmlBody))]))

	// Extract SAMLResponse value using regex - try multiple patterns
	patterns := []string{
		`name="SAMLResponse"\s+value="([^"]+)"`,
		`value="([^"]+)"\s+name="SAMLResponse"`,
		`<input[^>]*name="SAMLResponse"[^>]*value="([^"]+)"[^>]*>`,
		`<input[^>]*value="([^"]+)"[^>]*name="SAMLResponse"[^>]*>`,
	}
	
	var encodedResponse string
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(htmlBody)
		if len(matches) >= 2 {
			encodedResponse = matches[1]
			break
		}
	}
	
	if encodedResponse == "" {
		slog.Error("SAMLResponse not found in HTML", slog.String("html_snippet", htmlBody[:min(200, len(htmlBody))]))
		return "", fmt.Errorf("SAMLResponse not found in HTML")
	}

	// Decode HTML entities
	encodedResponse = html.UnescapeString(encodedResponse)
	slog.Info("Extracted encoded SAML response", slog.Int("encoded_length", len(encodedResponse)))
	
	// Decode the SAML response
	decodedResponse, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		slog.Error("Failed to decode SAMLResponse", slog.String("error", err.Error()))
		return "", fmt.Errorf("failed to decode SAMLResponse: %w", err)
	}

	originalXML := string(decodedResponse)
	slog.Info("Decoded SAML response XML", 
		slog.Int("xml_length", len(originalXML)),
		slog.String("xml_preview", originalXML[:min(300, len(originalXML))]))

	// Fix the SAML response XML
	fixedXML := fixSAMLAssertionVersion(originalXML)

	// Check if any changes were made
	if originalXML == fixedXML {
		slog.Info("No changes needed - Version attributes already present")
	} else {
		slog.Info("Applied XML fixes", 
			slog.Int("original_length", len(originalXML)),
			slog.Int("fixed_length", len(fixedXML)))
	}

	// Log the complete fixed XML for debugging
	slog.Info("Complete fixed SAML XML", slog.String("xml", fixedXML))

	// Re-encode the fixed response
	fixedEncoded := base64.StdEncoding.EncodeToString([]byte(fixedXML))

	// Replace in the HTML
	fixedHTML := strings.Replace(htmlBody, encodedResponse, fixedEncoded, 1)

	slog.Info("Fixed SAML response - added Version attributes")
	
	return fixedHTML, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fixSAMLAssertionVersion(xmlStr string) string {
	slog.Info("Starting XML Version attribute fix")
	
	// Add Version="2.0" to Assertion elements that don't have it
	// Match <saml:Assertion or <saml2:Assertion or <Assertion
	assertionRe := regexp.MustCompile(`<(\w*:)?Assertion\s+([^>]*?)>`)
	
	assertionMatches := assertionRe.FindAllString(xmlStr, -1)
	slog.Info("Found Assertion elements", slog.Int("count", len(assertionMatches)))
	for i, match := range assertionMatches {
		slog.Info("Assertion element found", 
			slog.Int("index", i),
			slog.String("element", match),
			slog.Bool("has_version", strings.Contains(match, "Version=")))
	}
	
	fixedXML := assertionRe.ReplaceAllStringFunc(xmlStr, func(match string) string {
		// Check if Version attribute already exists and has a valid value
		if strings.Contains(match, `Version="2.0"`) {
			slog.Info("Assertion already has correct Version attribute", slog.String("element", match))
			return match
		}
		
		// Check if Version attribute exists but is empty or has wrong value
		if strings.Contains(match, "Version=") {
			// Replace empty version or wrong version with "2.0"
			versionRe := regexp.MustCompile(`Version="[^"]*"`)
			fixed := versionRe.ReplaceAllString(match, `Version="2.0"`)
			slog.Info("Fixed Assertion Version attribute", 
				slog.String("original", match),
				slog.String("fixed", fixed))
			return fixed
		}
		
		// Add Version="2.0" after the opening tag
		if strings.HasSuffix(match, ">") {
			fixed := strings.TrimSuffix(match, ">") + ` Version="2.0">`
			slog.Info("Added Version attribute to Assertion element", 
				slog.String("original", match),
				slog.String("fixed", fixed))
			return fixed
		}
		return match
	})

	// Also fix Response elements
	responseRe := regexp.MustCompile(`<(\w*:)?Response\s+([^>]*?)>`)
	
	responseMatches := responseRe.FindAllString(fixedXML, -1)
	slog.Info("Found Response elements", slog.Int("count", len(responseMatches)))
	for i, match := range responseMatches {
		slog.Info("Response element found", 
			slog.Int("index", i),
			slog.String("element", match),
			slog.Bool("has_version", strings.Contains(match, "Version=")))
	}
	
	fixedXML = responseRe.ReplaceAllStringFunc(fixedXML, func(match string) string {
		// Check if Version attribute already exists and has a valid value
		if strings.Contains(match, `Version="2.0"`) {
			slog.Info("Response already has correct Version attribute", slog.String("element", match))
			return match
		}
		
		// Check if Version attribute exists but is empty or has wrong value
		if strings.Contains(match, "Version=") {
			// Replace empty version or wrong version with "2.0"
			versionRe := regexp.MustCompile(`Version="[^"]*"`)
			fixed := versionRe.ReplaceAllString(match, `Version="2.0"`)
			slog.Info("Fixed Response Version attribute", 
				slog.String("original", match),
				slog.String("fixed", fixed))
			return fixed
		}
		
		// Add Version="2.0" after the opening tag
		if strings.HasSuffix(match, ">") {
			fixed := strings.TrimSuffix(match, ">") + ` Version="2.0">`
			slog.Info("Added Version attribute to Response element", 
				slog.String("original", match),
				slog.String("fixed", fixed))
			return fixed
		}
		return match
	})

	slog.Info("Completed XML Version attribute fix")
	return fixedXML
}

// responseRecorder captures the response
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}