package proxy

import (
	"log/slog"
	"net/http"
)

// handlePing handles the /ping health check endpoint.
func handlePing(w http.ResponseWriter, _ *http.Request) {
	// Health check endpoint
	_, err := w.Write([]byte("pong"))
	if err != nil {
		respondWithInternalServerError(w, slog.String("operation", "write ping response"))
	}
}
