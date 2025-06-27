package main

import (
	// "crypto/rand" // No longer used for dynamic cert generation
	"crypto/rsa"
	"crypto/x509"
	// "crypto/x509/pkix" // No longer used for dynamic cert generation
	"encoding/pem" // Needed for parsing PEM encoded key/cert files
	"encoding/xml" // For xml.MarshalIndent
	"errors"       // For custom errors
	"fmt"
	"log"
	// "math/big" // No longer used for dynamic cert generation
	"net/http"
	"net/url"
	"os" // For os.Getenv and os.ReadFile
	// "time" // No longer used for dynamic cert generation

	"github.com/crewjam/saml"
	"github.com/kelseyhightower/envconfig" // Added for envconfig
)

// Config holds all configuration for the application, loaded from environment variables.
type Config struct {
	// Proxy SP Settings
	ProxyEntityID      string `envconfig:"PROXY_ENTITY_ID" default:"http://localhost:8080/metadata"`
	ProxyAcsURLStr     string `envconfig:"PROXY_ACS_URL" default:"http://localhost:8080/sso/acs"`
	ProxyMetadataURLStr string `envconfig:"PROXY_METADATA_URL" default:"http://localhost:8080/metadata"`
	ProxyPrivateKeyPath string `envconfig:"PROXY_PRIVATE_KEY_PATH" required:"true"`
	ProxyCertificatePath string `envconfig:"PROXY_CERTIFICATE_PATH" required:"true"`

	// Parsed values (not directly from envconfig)
	ProxyAcsURL        *url.URL          `ignored:"true"`
	ProxyMetadataURL   *url.URL          `ignored:"true"`
	ProxyPrivateKey    *rsa.PrivateKey   `ignored:"true"`
	ProxyCertificate   *x509.Certificate `ignored:"true"`

	// Upstream IdP Settings (optional for now)
	IdpEntityID    string `envconfig:"IDP_ENTITY_ID"`
	IdpSsoURLStr   string `envconfig:"IDP_SSO_URL"`
	IdpCertificatePath string `envconfig:"IDP_CERTIFICATE_PATH"`

	// Parsed IdP values (not directly from envconfig)
	IdpSsoURL      *url.URL          `ignored:"true"`
	IdpCertificate *x509.Certificate `ignored:"true"`

	// Server Settings
	ServerListenAddress string `envconfig:"SERVER_LISTEN_ADDRESS" default:":8080"`
}

// loadConfig loads configuration from environment variables and returns a Config struct.
func loadConfig() (*Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}

	// Parse URLs
	cfg.ProxyAcsURL, err = url.Parse(cfg.ProxyAcsURLStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PROXY_ACS_URL_STR '%s': %w", cfg.ProxyAcsURLStr, err)
	}
	cfg.ProxyMetadataURL, err = url.Parse(cfg.ProxyMetadataURLStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PROXY_METADATA_URL_STR '%s': %w", cfg.ProxyMetadataURLStr, err)
	}

	// Load and parse Proxy Private Key
	keyData, err := os.ReadFile(cfg.ProxyPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file '%s': %w", cfg.ProxyPrivateKeyPath, err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key file '%s'", cfg.ProxyPrivateKeyPath)
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		pkcs8Key, errPkcs8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errPkcs8 != nil {
			return nil, fmt.Errorf("failed to parse private key (tried PKCS#1 and PKCS#8) from '%s': pkcs1_err=%v, pkcs8_err=%v", cfg.ProxyPrivateKeyPath, err, errPkcs8)
		}
		var ok bool
		privKey, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key in '%s' is not an RSA private key (type: %T)", cfg.ProxyPrivateKeyPath, pkcs8Key)
		}
	}
	cfg.ProxyPrivateKey = privKey

	// Load and parse Proxy Certificate
	certData, err := os.ReadFile(cfg.ProxyCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file '%s': %w", cfg.ProxyCertificatePath, err)
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate file '%s'", cfg.ProxyCertificatePath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from '%s': %w", cfg.ProxyCertificatePath, err)
	}
	cfg.ProxyCertificate = cert

	// Load and parse IdP Certificate (if path is provided)
	if cfg.IdpSsoURLStr != "" {
		cfg.IdpSsoURL, err = url.Parse(cfg.IdpSsoURLStr)
		if err != nil {
			log.Printf("Warning: Failed to parse IDP_SSO_URL_STR '%s': %v. It will be ignored.", cfg.IdpSsoURLStr, err)
			cfg.IdpSsoURL = nil
		}
	}

	if cfg.IdpCertificatePath != "" {
		idpCertData, err := os.ReadFile(cfg.IdpCertificatePath)
		if err != nil {
			log.Printf("Warning: Failed to read IdP certificate file '%s': %v. It will be ignored.", cfg.IdpCertificatePath, err)
		} else {
			idpCertBlock, _ := pem.Decode(idpCertData)
			if idpCertBlock == nil {
				log.Printf("Warning: Failed to decode PEM block from IdP certificate file '%s'. It will be ignored.", cfg.IdpCertificatePath)
			} else {
				idpCert, errParseCert := x509.ParseCertificate(idpCertBlock.Bytes) // Use new error variable
				if errParseCert != nil { // Check the new error variable
					log.Printf("Warning: Failed to parse IdP certificate from '%s': %v. It will be ignored.", cfg.IdpCertificatePath, errParseCert)
				} else {
					cfg.IdpCertificate = idpCert
				}
			}
		}
	}

	return &cfg, nil // Return address of cfg
}


/*
config.yml (example structure)

# Proxy (This Service Provider) settings
proxy:
  entity_id: "http://localhost:8080/metadata"
  assertion_consumer_service_url: "http://localhost:8080/sso/acs"
  # single_logout_service_url: "http://localhost:8080/sso/slo" # Future
  private_key_path: "proxy.key"
  certificate_path: "proxy.crt"
  metadata_url: "http://localhost:8080/metadata" # Should match entity_id typically

# Upstream Identity Provider settings
idp:
  entity_id: "https://idp.example.com/saml/metadata" # Example IdP
  sso_service_url: "https://idp.example.com/saml/sso"
  # single_logout_service_url: "https://idp.example.com/saml/slo" # Future
  certificate_path: "idp.crt" # Path to IdP's public certificate for verifying signatures
  # metadata_url: "https://idp.example.com/saml/metadata" # Optional: if provided, other IdP settings might be fetched from here

server:
  listen_address: ":8080"

*/

// Placeholder for configuration values have been removed as they are now loaded from env vars.

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "pong")
	})

	samlSPHandler, err := newSamlServiceProvider(cfg)
	if err != nil {
		log.Fatalf("Failed to create SAML Service Provider: %v", err)
	}
	http.Handle("/metadata", samlSPHandler)
	// The metadata handler itself is now created by newSamlServiceProvider

	log.Printf("Starting server on %s...", cfg.ServerListenAddress)
	log.Printf("Ping endpoint: http://localhost%s/ping", cfg.ServerListenAddress) // Assuming localhost for ping
	// Construct metadata URL carefully based on listen address if it's not always localhost
	// For now, assume metadata URL in config is the externally reachable one.
	log.Printf("SAML SP Metadata: %s", cfg.ProxyMetadataURL.String())


	if err := http.ListenAndServe(cfg.ServerListenAddress, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// newSamlServiceProvider creates and configures a new SAML ServiceProvider http.Handler instance
// using the provided configuration.
func newSamlServiceProvider(cfg *Config) (http.Handler, error) {
	// Dynamic key/cert generation is removed. Using values from cfg.
	if cfg.ProxyPrivateKey == nil {
		return nil, errors.New("proxy private key not loaded in config")
	}
	if cfg.ProxyCertificate == nil {
		return nil, errors.New("proxy certificate not loaded in config")
	}
	if cfg.ProxyMetadataURL == nil {
		return nil, errors.New("proxy metadata URL not loaded in config")
	}
	if cfg.ProxyAcsURL == nil {
		return nil, errors.New("proxy ACS URL not loaded in config")
	}


	samlSP := saml.ServiceProvider{
		EntityID:    cfg.ProxyEntityID,
		Key:         cfg.ProxyPrivateKey,
		Certificate: cfg.ProxyCertificate,
		MetadataURL: *cfg.ProxyMetadataURL,
		AcsURL:      *cfg.ProxyAcsURL,
		// AuthnRequestsSigned: true, // Future consideration
		// WantAssertionsSigned: true, // Future consideration
	}

	// Create an http.HandlerFunc to serve the metadata
	metadataHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md := samlSP.Metadata() // Get metadata from saml.ServiceProvider; returns *EntityDescriptor, no error
		xmlBytes, err := xml.MarshalIndent(md, "", "  ") // Use xml.MarshalIndent
		if err != nil {
			log.Printf("Error marshalling SAML metadata to XML: %v", err)
			http.Error(w, "Failed to marshal SAML metadata", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(xmlBytes)
	})

	// For the ACS endpoint later, we will likely use `samlsp.Middleware`
	// and mount it at a suitable path (e.g., "/sso/acs" directly or "/sso/" and let it handle "acs").
	// For now, only metadata is served.
	return metadataHandler, nil

	// --- Old approach using samlsp.New() or direct samlsp.ServiceProvider (kept for reference) ---
	// The core issue was that `samlsp.Middleware` (returned by `samlsp.New`) hardcodes
	// path prefixes like "/saml/". If we want different paths like "/metadata",
	// we might need to wrap it or handle routing carefully.
	//
	// opts := samlsp.Options{
	// 	EntityID: proxyEntityID,
	// 	Key: privKey,
	// 	Certificate: certPem, // samlsp.Options expects PEM bytes for Certificate
	// 	AcsURL: parsedAcsURL,
	// 	MetadataURL: parsedMetadataURL,
	// 	// BaseURL can be tricky. If set, it might override AcsURL/MetadataURL path construction.
	// 	// For example, if BaseURL is http://localhost:8080, AcsURL might become http://localhost:8080/saml/acs
	// 	// Let's try with it commented out first, relying on explicit AcsURL/MetadataURL.
	// 	// URL: *baseURL, // Example: http://localhost:8080
	// }
	//
	// samlMiddleware, err := samlsp.New(opts)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create samlsp.Middleware: %w", err)
	// }
	// return samlMiddleware, nil
}
