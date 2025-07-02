package proxy

import (
	"net/http"
	"net/url"
)

func mustParseURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}

	return *u
}

type fakeResponseWriter struct {
	content    []byte
	statusCode int
	header     http.Header
}

func newFakeResponseWriter() *fakeResponseWriter {
	return &fakeResponseWriter{
		header:  make(http.Header),
		content: make([]byte, 0),
	}
}

func (w *fakeResponseWriter) Header() http.Header {
	return w.header
}

func (w *fakeResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w *fakeResponseWriter) Write(b []byte) (int, error) {
	w.content = append(w.content, b...)

	return 0, nil
}
