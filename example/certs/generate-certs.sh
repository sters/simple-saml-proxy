#!/bin/bash

# Generate certificates for SAML proxy integration testing
# This script creates self-signed certificates for testing purposes only

set -e

# Create certificates directory if it doesn't exist
mkdir -p "$(dirname "$0")"
cd "$(dirname "$0")"

# Generate proxy certificate
echo "Generating proxy certificate..."
openssl req -new -x509 -days 365 -nodes \
    -out proxy.crt \
    -keyout proxy.key \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=simple-saml-proxy"

# Generate keycloak IdP certificate
echo "Generating Keycloak IdP certificate..."
openssl req -new -x509 -days 365 -nodes \
    -out keycloak-idp.crt \
    -keyout keycloak-idp.key \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=keycloak-idp"

# Generate keycloak SP certificate
echo "Generating Keycloak SP certificate..."
openssl req -new -x509 -days 365 -nodes \
    -out keycloak-sp.crt \
    -keyout keycloak-sp.key \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=keycloak-sp"

# Set appropriate permissions
chmod 600 *.key
chmod 644 *.crt

echo "Certificates generated successfully!"
echo "Files created:"
echo "  - proxy.crt / proxy.key"
echo "  - keycloak-idp.crt / keycloak-idp.key"
echo "  - keycloak-sp.crt / keycloak-sp.key"