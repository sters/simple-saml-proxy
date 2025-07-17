package proxy

import (
	"log/slog"
	"net/http"
)

// Standard error responses.
const (
	ErrInvalidRequest   = "Invalid request"
	ErrInternalServer   = "Internal server error"
	ErrInvalidLogout    = "Invalid logout request"
	ErrUnauthorized     = "Unauthorized"
	ErrBadRequest       = "Bad request"
	ErrMethodNotAllowed = "Method not allowed"
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
