package proxy

import (
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

// IDPConfig holds the configuration for a single Identity Provider.
type IDPConfig struct {
	ID              string `envconfig:"ID"`
	EntityID        string `envconfig:"ENTITY_ID"        required:"true"`
	SSOURL          string `envconfig:"SSO_URL"          required:"true"`
	CertificatePath string `envconfig:"CERTIFICATE_PATH" required:"true"`
}

// Config holds all the configuration parameters for the SAML proxy.
type Config struct {
	Proxy struct {
		EntityID        string `default:"http://localhost:8080/metadata" envconfig:"ENTITY_ID"`
		AcsURL          string `default:"http://localhost:8080/sso/acs"  envconfig:"ACS_URL"`
		MetadataURL     string `default:"http://localhost:8080/metadata" envconfig:"METADATA_URL"`
		PrivateKeyPath  string `envconfig:"PRIVATE_KEY_PATH"             required:"true"`
		CertificatePath string `envconfig:"CERTIFICATE_PATH"             required:"true"`
		CookieName      string `default:"idp_selection"                  envconfig:"COOKIE_NAME"`
	} `envconfig:"PROXY"`

	// For backward compatibility
	IDP IDPConfig `envconfig:"IDP"`

	// Support for multiple IDPs
	IDPs []IDPConfig `envconfig:"IDPS"`

	Server struct {
		ListenAddress string `default:":8080" envconfig:"LISTEN_ADDRESS"`
	} `envconfig:"SERVER"`
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (Config, error) {
	var config Config

	// Print all environment variables for debugging
	slog.Info("Environment variables:")
	for _, env := range os.Environ() {
		slog.Info(env)
	}

	// Process the proxy and server configuration
	err := envconfig.Process("", &config)
	if err != nil {
		slog.Info("Error processing config", slog.Any("error", err))
		// Continue anyway, we'll try to parse the IDPs manually
	}

	slog.Info("Config after processing", slog.Any("IDP", config.IDP), slog.Any("IDPs", config.IDPs))

	// Clear the IDPs slice to avoid duplicates
	config.IDPs = []IDPConfig{}

	// For backward compatibility, if a single IDP is configured, add it to the IDPs slice
	if config.IDP.EntityID != "" && config.IDP.SSOURL != "" && config.IDP.CertificatePath != "" {
		// If ID is not set, use a default ID
		if config.IDP.ID == "" {
			config.IDP.ID = "default"
		}
		config.IDPs = append(config.IDPs, config.IDP)
		slog.Info("Added single IDP to IDPs slice", slog.Any("IDPs", config.IDPs))
	}

	// Look for additional IDPs configured with IDP1_, IDP2_, etc. prefixes
	for _, env := range os.Environ() {
		key, value, _ := strings.Cut(env, "=")
		if strings.HasPrefix(key, "IDP") && strings.HasSuffix(key, "_ID") && key != "IDP_ID" {
			prefix := key[:len(key)-3] // Remove "_ID" suffix
			id := value
			entityID := os.Getenv(prefix + "_ENTITY_ID")
			ssoURL := os.Getenv(prefix + "_SSO_URL")
			certPath := os.Getenv(prefix + "_CERTIFICATE_PATH")

			// Only add if all required fields are present
			if entityID != "" && ssoURL != "" && certPath != "" {
				idp := IDPConfig{
					ID:              id,
					EntityID:        entityID,
					SSOURL:          ssoURL,
					CertificatePath: certPath,
				}
				config.IDPs = append(config.IDPs, idp)
				slog.Info("Added IDP from environment", slog.Any("idp", idp))
			}
		}
	}

	// Validate that we have at least one IDP
	if len(config.IDPs) == 0 {
		slog.Info("No IDPs configured")

		return config, errors.New("at least one IDP must be configured")
	}

	// Process the server configuration again to make sure it's set correctly
	var serverConfig struct {
		Server struct {
			ListenAddress string `default:":8080" envconfig:"LISTEN_ADDRESS"`
		} `envconfig:"SERVER"`
	}
	err = envconfig.Process("", &serverConfig)
	if err == nil {
		config.Server = serverConfig.Server
	}

	slog.Info("Final config", slog.Any("IDPs", config.IDPs), slog.Any("Server", config.Server))

	return config, nil
}
