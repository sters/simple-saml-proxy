package proxy

import (
	"crypto/rand"
	"io"
	"net/http"
)

const (
	cookieNameAuthRequestID = "authID"
	cookieNameIDPID         = "idpID"
	relayStateLength        = 42
)

// isSecureCookie determines if cookies should be secure based on the request.
func isSecureCookie(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, rv); err != nil {
		return nil
	}

	return rv
}
