package proxy

import "net/http"

// handleIDPInitiated handles the IdP-initiated flow endpoint.
func handleIDPInitiated(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "IdP-Initiated flow not yet implemented", http.StatusNotImplemented)
}
