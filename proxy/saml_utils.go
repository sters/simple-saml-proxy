package proxy

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

var (
	errNotFlateResetter           = errors.New("reader does not implement flate.Resetter")
	errIssueInstantInFuture       = errors.New("issue instant is in the future")
	errIssueInstantTooOld         = errors.New("issue instant is too old")
	errLogoutRequestMissingIssuer = errors.New("logout request missing issuer")
)

// decodeDeflatedData decompresses deflated data with a size limit to prevent decompression bombs.
func decodeDeflatedData(compressedData []byte) ([]byte, error) {
	reader := flate.NewReader(nil)
	resetter, ok := reader.(flate.Resetter)
	if !ok {
		return nil, errNotFlateResetter
	}
	err := resetter.Reset(io.NopCloser(bytes.NewReader(compressedData)), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to reset reader: %w", err)
	}
	defer reader.Close()

	// Limit to 10MB to prevent decompression bombs
	limitedReader := io.LimitReader(reader, 10*1024*1024)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	return data, nil
}

// validateSAMLIssueInstant checks if the SAML message was issued recently to prevent replay attacks.
// It accepts custom error messages for different SAML message types.
func validateSAMLIssueInstant(issueInstant time.Time, entityType string) error {
	const maxAge = 5 * time.Minute

	now := time.Now()
	age := now.Sub(issueInstant)

	if age < 0 {
		// Issue instant is in the future
		return fmt.Errorf("%s %w: %v", entityType, errIssueInstantInFuture, issueInstant)
	}

	if age > maxAge {
		return fmt.Errorf("%s %w: issued %v ago", entityType, errIssueInstantTooOld, age)
	}

	return nil
}

// parseSAMLMessage is a generic parser for SAML messages that handles base64 decoding,
// decompression, and XML unmarshaling.
func parseSAMLMessage(samlParam string, target interface{}, messageType string) error {
	// Base64 decode (the samlParam should already be URL-decoded by Go's query parsing)
	compressed, err := base64.StdEncoding.DecodeString(samlParam)
	if err != nil {
		return fmt.Errorf("failed to base64 decode %s: %w", messageType, err)
	}

	// Try to decompress using flate
	decompressed, err := decodeDeflatedData(compressed)
	if err != nil {
		// Try without decompression in case it's not compressed
		decompressed = compressed
	}

	// Unmarshal XML
	if err := xml.Unmarshal(decompressed, target); err != nil {
		return fmt.Errorf("failed to unmarshal %s: %w", messageType, err)
	}

	return nil
}

// parseLogoutRequest parses a SAML logout request from the SAMLRequest parameter.
func parseLogoutRequest(samlRequestParam string) (*crewjamsaml.LogoutRequest, error) {
	var logoutRequest crewjamsaml.LogoutRequest
	if err := parseSAMLMessage(samlRequestParam, &logoutRequest, "logout request"); err != nil {
		return nil, err
	}

	// Validate required fields
	if logoutRequest.Issuer == nil || logoutRequest.Issuer.Value == "" {
		return nil, errLogoutRequestMissingIssuer
	}

	return &logoutRequest, nil
}

// parseLogoutResponse parses a SAML logout response.
func parseLogoutResponse(samlResponseParam string) (*crewjamsaml.LogoutResponse, error) {
	var logoutResponse crewjamsaml.LogoutResponse
	if err := parseSAMLMessage(samlResponseParam, &logoutResponse, "logout response"); err != nil {
		return nil, err
	}

	return &logoutResponse, nil
}
