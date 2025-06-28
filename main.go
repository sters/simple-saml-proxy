package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/kelseyhightower/envconfig"
)

// Config holds all the configuration parameters for the SAML proxy
type Config struct {
	Proxy struct {
		EntityID        string `envconfig:"ENTITY_ID" default:"http://localhost:8080/metadata"`
		AcsURL          string `envconfig:"ACS_URL" default:"http://localhost:8080/sso/acs"`
		MetadataURL     string `envconfig:"METADATA_URL" default:"http://localhost:8080/metadata"`
		PrivateKeyPath  string `envconfig:"PRIVATE_KEY_PATH" required:"true"`
		CertificatePath string `envconfig:"CERTIFICATE_PATH" required:"true"`
	} `envconfig:"PROXY"`

	IdP struct {
		EntityID        string `envconfig:"ENTITY_ID" required:"true"`
		SSOURL          string `envconfig:"SSO_URL" required:"true"`
		CertificatePath string `envconfig:"CERTIFICATE_PATH" required:"true"`
	} `envconfig:"IDP"`

	Server struct {
		ListenAddress string `envconfig:"LISTEN_ADDRESS" default:":8080"`
	} `envconfig:"SERVER"`
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (Config, error) {
	var config Config
	err := envconfig.Process("", &config)
	return config, err
}

// LoadCertificate loads and parses the SP certificate and private key
func LoadCertificate(certPath, keyPath string) (tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	return keyPair, err
}

// CreateSAMLServiceProvider creates a new SAML Service Provider
func CreateSAMLServiceProvider(config Config, keyPair tls.Certificate) (*samlsp.Middleware, error) {
	// Note: In a production environment, you would load and validate the IdP certificate
	// For simplicity, we're skipping this step in this example

	return samlsp.New(samlsp.Options{
		URL:               *mustParseURL(config.Proxy.EntityID),
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       &saml.EntityDescriptor{EntityID: config.IdP.EntityID},
		AllowIDPInitiated: true,
	})
}

// ConfigureIdPMetadata configures the IdP metadata for the SAML Service Provider
func ConfigureIdPMetadata(samlSP *samlsp.Middleware, idpSSOURL string) (*url.URL, error) {
	idpMetadataURL, err := url.Parse(idpSSOURL)
	if err != nil {
		return nil, err
	}

	samlSP.ServiceProvider.IDPMetadata.IDPSSODescriptors = []saml.IDPSSODescriptor{
		{
			SingleSignOnServices: []saml.Endpoint{
				{
					Binding:  saml.HTTPRedirectBinding,
					Location: idpSSOURL,
				},
			},
		},
	}

	return idpMetadataURL, nil
}

// SetupHTTPHandlers sets up the HTTP handlers for the SAML proxy
func SetupHTTPHandlers(samlSP *samlsp.Middleware, idpMetadataURL *url.URL) *http.ServeMux {
	mux := http.NewServeMux()

	// Metadata endpoint
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		samlSP.ServeMetadata(w, r)
	})

	// SSO initiation endpoint
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		relayState := r.URL.Query().Get("RelayState")
		if relayState == "" {
			relayState = "/"
		}

		// Redirect to the IdP for authentication
		http.Redirect(w, r, idpMetadataURL.String(), http.StatusFound)
	})

	// ACS (Assertion Consumer Service) endpoint
	mux.HandleFunc("/sso/acs", samlSP.ServeACS)

	// Health check endpoint
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	return mux
}

// StartServer starts the HTTP server with the given configuration and handler
func StartServer(config Config, handler http.Handler) error {
	server := &http.Server{
		Addr:    config.Server.ListenAddress,
		Handler: handler,
	}

	log.Printf("Starting SAML proxy on %s", config.Server.ListenAddress)
	log.Printf("Metadata URL: %s", config.Proxy.MetadataURL)
	log.Printf("ACS URL: %s", config.Proxy.AcsURL)
	log.Printf("SSO URL: %s/sso", config.Proxy.EntityID)

	return server.ListenAndServe()
}

func main() {
	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to process config: %v", err)
	}

	// Load certificates
	keyPair, err := LoadCertificate(config.Proxy.CertificatePath, config.Proxy.PrivateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load SP certificate and key: %v", err)
	}

	// Create SAML Service Provider
	samlSP, err := CreateSAMLServiceProvider(config, keyPair)
	if err != nil {
		log.Fatalf("Failed to create SAML SP: %v", err)
	}

	// Configure IdP metadata
	idpMetadataURL, err := ConfigureIdPMetadata(samlSP, config.IdP.SSOURL)
	if err != nil {
		log.Fatalf("Failed to parse IdP SSO URL: %v", err)
	}

	// Set up HTTP handlers
	mux := SetupHTTPHandlers(samlSP, idpMetadataURL)

	// Start the server
	err = StartServer(config, mux)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// Helper function to parse URLs and panic on error
func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
