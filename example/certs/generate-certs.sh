#!/bin/bash

# Generate certificates for SAML proxy integration testing
# This script creates self-signed certificates for testing purposes only

set -e

# Create certificates directory if it doesn't exist
mkdir -p "$(dirname "$0")"
cd "$(dirname "$0")"

# Function to generate a certificate
generate_cert() {
    local name=$1
    local cn=$2
    
    echo "Generating $name certificate..."
    openssl req -new -x509 -days 365 -nodes \
        -out "$name.crt" \
        -keyout "$name.key" \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=$cn"
}

# Generate certificates for all services
generate_cert "proxy" "simple-saml-proxy"
generate_cert "keycloak-idp" "keycloak-idp"
generate_cert "keycloak-sp" "keycloak-sp"

# Set appropriate permissions
chmod 600 *.key
chmod 644 *.crt

echo "Certificates generated successfully!"
echo "Files created:"
echo "  - proxy.crt / proxy.key"
echo "  - keycloak-idp.crt / keycloak-idp.key"
echo "  - keycloak-sp.crt / keycloak-sp.key"