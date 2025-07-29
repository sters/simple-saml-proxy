package proxy

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
)

const (
	cookieNameAuthRequestID = "authID"
	cookieNameIDPID         = "idpID"
	relayStateLength        = 42
)

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

func deflateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to create deflate writer: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		writer.Close()

		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close deflate writer: %w", err)
	}

	return buf.Bytes(), nil
}
