package proxy

import (
	"errors"
	"fmt"

	"github.com/caarlos0/env/v11"
)

// IDPConfig holds the configuration for a single Identity Provider.
type IDPConfig struct {
	ID              string `env:"ID,required"`
	EntityID        string `env:"ENTITY_ID"`
	SSOURL          string `env:"SSO_URL"`
	CertificatePath string `env:"CERTIFICATE_PATH"`
	MetadataURL     string `env:"METADATA_URL"`
}

type SPConfig struct {
	EntityID    string `env:"ENTITY_ID"`
	AcsURL      string `env:"ACS_URL"`
	MetadataURL string `env:"METADATA_URL"`
}

// Config holds all the configuration parameters for the SAML proxy.
type Config struct {
	Proxy struct {
		EntityID        string     `env:"ENTITY_ID"                 envDefault:"http://localhost:8080"`
		AcsURL          string     `env:"ACS_URL"                   envDefault:"http://localhost:8080/sso/acs"`
		MetadataURL     string     `env:"METADATA_URL"              envDefault:"http://localhost:8080/metadata"`
		PrivateKeyPath  string     `env:"PRIVATE_KEY_PATH,required"`
		CertificatePath string     `env:"CERTIFICATE_PATH,required"`
		AllowedSP       []SPConfig `envPrefix:"ALLOWED_SP_"`
	} `envPrefix:"PROXY_"`

	// Support for multiple IDP
	IDP []IDPConfig `envPrefix:"IDP_"`

	Server struct {
		ListenAddress string `env:"LISTEN_ADDRESS" envDefault:":8080"`
	} `envPrefix:"SERVER_"`
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (Config, error) {
	var config Config

	if err := env.Parse(&config); err != nil {
		return config, fmt.Errorf("failed to parse environment variables: %w", err)
	}

	if len(config.IDP) == 0 {
		return config, errors.New("at least one IDP must be configured")
	}

	return config, nil
}
