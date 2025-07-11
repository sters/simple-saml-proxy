#!/bin/bash

# Generate certificates for the SAML proxy, IdP, and SP

# Create proxy certificate
openssl req -x509 -newkey rsa:4096 -keyout proxy.key -out proxy.crt -days 365 -nodes -subj "/CN=simple-saml-proxy"

# Create IdP certificate
openssl req -x509 -newkey rsa:4096 -keyout idp.key -out idp.crt -days 365 -nodes -subj "/CN=test-idp"

# Create SP certificate
openssl req -x509 -newkey rsa:4096 -keyout sp.key -out sp.crt -days 365 -nodes -subj "/CN=test-sp"

echo "Certificates generated successfully!"