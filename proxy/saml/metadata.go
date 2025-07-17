package saml

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/sters/simple-saml-proxy/config"
	"github.com/zitadel/saml/pkg/provider/xml"
)

const (
	defaultMaxRetries   = 5
	defaultInitialDelay = 1 * time.Second
	defaultMaxDelay     = 30 * time.Second
)

// retryWithBackoff executes an operation with exponential backoff retry logic.
func retryWithBackoff[T any](ctx context.Context, cfg config.Config, urlStr string, operation func() (T, error)) (T, error) {
	var lastErr error
	var zero T

	delay := cfg.Metadata.InitialDelay
	if delay == 0 {
		delay = defaultInitialDelay
	}
	maxRetries := cfg.Metadata.MaxRetries
	if maxRetries == 0 {
		maxRetries = defaultMaxRetries
	}
	maxDelay := cfg.Metadata.MaxDelay
	if maxDelay == 0 {
		maxDelay = defaultMaxDelay
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			slog.Info("Retrying operation",
				slog.String("url", urlStr),
				slog.Int("attempt", attempt),
				slog.Duration("delay", delay))

			select {
			case <-time.After(delay):
				// Continue with retry
			case <-ctx.Done():
				return zero, fmt.Errorf("context cancelled while retrying metadata read: %w", ctx.Err())
			}
		}

		result, err := operation()
		if err == nil {
			if attempt > 0 {
				slog.Info("Successfully completed operation after retry",
					slog.String("url", urlStr),
					slog.Int("attempts", attempt+1))
			}

			return result, nil
		}

		lastErr = err
		slog.Warn("Operation failed",
			slog.String("url", urlStr),
			slog.Int("attempt", attempt+1),
			slog.Int("max_attempts", maxRetries+1),
			slog.Any("error", err))

		// Exponential backoff
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}

	return zero, fmt.Errorf("failed to read metadata after %d attempts: %w", maxRetries+1, lastErr)
}

// FetchMetadataWithRetry attempts to fetch SAML metadata with exponential backoff retry logic.
func FetchMetadataWithRetry(ctx context.Context, client *http.Client, metadataURL url.URL, cfg config.Config) (*saml.EntityDescriptor, error) {
	return retryWithBackoff(ctx, cfg, metadataURL.String(), func() (*saml.EntityDescriptor, error) {
		return samlsp.FetchMetadata(ctx, client, metadataURL)
	})
}

// ReadMetadataFromURLWithRetry attempts to read SAML metadata from URL with exponential backoff retry logic.
func ReadMetadataFromURLWithRetry(ctx context.Context, client *http.Client, metadataURL string, cfg config.Config) ([]byte, error) {
	return retryWithBackoff(ctx, cfg, metadataURL, func() ([]byte, error) {
		return xml.ReadMetadataFromURL(client, metadataURL)
	})
}
