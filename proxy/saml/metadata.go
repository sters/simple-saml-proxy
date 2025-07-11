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
	defaultMaxRetries = 5
	defaultInitialDelay = 1 * time.Second
	defaultMaxDelay = 30 * time.Second
)

// FetchMetadataWithRetry attempts to fetch SAML metadata with exponential backoff retry logic.
func FetchMetadataWithRetry(ctx context.Context, client *http.Client, metadataURL url.URL, cfg config.Config) (*saml.EntityDescriptor, error) {
	var lastErr error
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
			slog.Info("Retrying metadata fetch",
				slog.String("url", metadataURL.String()),
				slog.Int("attempt", attempt),
				slog.Duration("delay", delay))

			select {
			case <-time.After(delay):
				// Continue with retry
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled while retrying metadata fetch: %w", ctx.Err())
			}
		}

		ed, err := samlsp.FetchMetadata(ctx, client, metadataURL)
		if err == nil {
			if attempt > 0 {
				slog.Info("Successfully fetched metadata after retry",
					slog.String("url", metadataURL.String()),
					slog.Int("attempts", attempt+1))
			}
			return ed, nil
		}

		lastErr = err
		slog.Warn("Failed to fetch metadata",
			slog.String("url", metadataURL.String()),
			slog.Int("attempt", attempt+1),
			slog.Int("max_attempts", maxRetries+1),
			slog.Any("error", err))

		// Exponential backoff with jitter
		delay = delay * 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}

	return nil, fmt.Errorf("failed to fetch metadata after %d attempts: %w", maxRetries+1, lastErr)
}

// ReadMetadataFromURLWithRetry attempts to read SAML metadata from URL with exponential backoff retry logic.
func ReadMetadataFromURLWithRetry(ctx context.Context, client *http.Client, metadataURL string, cfg config.Config) ([]byte, error) {
	var lastErr error
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
			slog.Info("Retrying metadata read",
				slog.String("url", metadataURL),
				slog.Int("attempt", attempt),
				slog.Duration("delay", delay))

			select {
			case <-time.After(delay):
				// Continue with retry
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled while retrying metadata read: %w", ctx.Err())
			}
		}

		metadataBytes, err := xml.ReadMetadataFromURL(client, metadataURL)
		if err == nil {
			if attempt > 0 {
				slog.Info("Successfully read metadata after retry",
					slog.String("url", metadataURL),
					slog.Int("attempts", attempt+1))
			}
			return metadataBytes, nil
		}

		lastErr = err
		slog.Warn("Failed to read metadata",
			slog.String("url", metadataURL),
			slog.Int("attempt", attempt+1),
			slog.Int("max_attempts", maxRetries+1),
			slog.Any("error", err))

		// Exponential backoff with jitter
		delay = delay * 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}

	return nil, fmt.Errorf("failed to read metadata after %d attempts: %w", maxRetries+1, lastErr)
}