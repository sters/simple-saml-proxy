package proxy

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
)

var errNotFlateResetter = errors.New("reader does not implement flate.Resetter")

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
