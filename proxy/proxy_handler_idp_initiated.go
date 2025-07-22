package proxy

import "net/http"

// handleIDPInitiated handles the IdP-initiated flow endpoint.
func handleIDPInitiated(w http.ResponseWriter, _ *http.Request) {
	respondWithNotImplemented(w, ErrNotImplemented)
}
