package proxy

import (
	"log/slog"
	"net/http"
)

// Standard error responses.
const (
	ErrInvalidRequest              = "Invalid request"
	ErrInternalServer              = "Internal server error"
	ErrInvalidLogout               = "Invalid logout request"
	ErrUnauthorized                = "Unauthorized"
	ErrBadRequest                  = "Bad request"
	ErrMethodNotAllowed            = "Method not allowed"
	ErrInvalidIDPID                = "Invalid IDP ID"
	ErrMissingSAMLRequest          = "Missing SAMLRequest parameter"
	ErrInvalidFormData             = "Invalid form data"
	ErrFailedToCreateLogoutRequest = "Failed to create logout request"
	ErrIDPDoesNotSupportSLO        = "Selected IdP does not support Single Logout"
	ErrNotImplemented              = "IdP-Initiated flow not yet implemented"
)

// respondWithError writes an error response with logging.
func respondWithError(w http.ResponseWriter, message string, statusCode int, logContext ...slog.Attr) {
	// Log the error with context
	logArgs := []any{
		slog.String("error", message),
		slog.Int("status", statusCode),
	}
	for _, attr := range logContext {
		logArgs = append(logArgs, attr)
	}

	slog.Error("HTTP error response", logArgs...)

	// Write the error response
	http.Error(w, message, statusCode)
}

// respondWithInternalServerError writes a 500 Internal Server Error response.
func respondWithInternalServerError(w http.ResponseWriter, logContext ...slog.Attr) {
	respondWithError(w, ErrInternalServer, http.StatusInternalServerError, logContext...)
}

// respondWithInvalidLogout writes a 400 Bad Request response for logout errors.
func respondWithInvalidLogout(w http.ResponseWriter, logContext ...slog.Attr) {
	respondWithError(w, ErrInvalidLogout, http.StatusBadRequest, logContext...)
}

// respondWithBadRequest writes a 400 Bad Request response.
func respondWithBadRequest(w http.ResponseWriter, message string, logContext ...slog.Attr) {
	respondWithError(w, message, http.StatusBadRequest, logContext...)
}

// respondWithInvalidRequest writes a 400 Bad Request response with "Invalid request" message.
func respondWithInvalidRequest(w http.ResponseWriter, logContext ...slog.Attr) {
	respondWithError(w, ErrInvalidRequest, http.StatusBadRequest, logContext...)
}

// respondWithMethodNotAllowed writes a 405 Method Not Allowed response.
func respondWithMethodNotAllowed(w http.ResponseWriter, logContext ...slog.Attr) {
	respondWithError(w, ErrMethodNotAllowed, http.StatusMethodNotAllowed, logContext...)
}
