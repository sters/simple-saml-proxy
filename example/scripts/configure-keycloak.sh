#!/bin/bash

# Configure Keycloak SP with SAML Identity Provider after startup
# This script configures the identity provider manually to avoid HTTPS validation during import

set -e

KEYCLOAK_SP_URL="http://localhost:12000"
KEYCLOAK_IDP_URL="http://localhost:11001"
PROXY_URL="http://localhost:10000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to get access token
get_access_token() {
    local keycloak_url=$1
    local realm=${2:-master}
    local username=${3:-admin}
    local password=${4:-admin}
    
    curl -s -X POST "$keycloak_url/realms/$realm/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username" \
        -d "password=$password" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" | \
        jq -r '.access_token'
}

# Function to create SAML identity provider
create_saml_idp() {
    local token=$1
    local keycloak_url=$2
    
    log "Creating SAML Identity Provider in Keycloak SP..."
    
    curl -s -X POST "$keycloak_url/admin/realms/sp-realm/identity-provider/instances" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "alias": "saml-proxy",
            "displayName": "SAML Proxy",
            "providerId": "saml",
            "enabled": true,
            "config": {
                "singleSignOnServiceUrl": "'"$PROXY_URL/sso"'",
                "backchannelSupported": "false",
                "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "postBindingAuthnRequest": "true",
                "postBindingResponse": "true",
                "wantAuthnRequestsSigned": "false",
                "wantAssertionsSigned": "true",
                "wantAssertionsEncrypted": "false",
                "forceAuthn": "false",
                "validateSignature": "false",
                "signSpMetadata": "false",
                "metadataDescriptorUrl": "'"$PROXY_URL/metadata"'"
            }
        }'
}

# Function to create identity provider mappers
create_idp_mappers() {
    local token=$1
    local keycloak_url=$2
    
    log "Creating Identity Provider mappers..."
    
    # Username mapper
    curl -s -X POST "$keycloak_url/admin/realms/sp-realm/identity-provider/instances/saml-proxy/mappers" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "username-mapper",
            "identityProviderAlias": "saml-proxy",
            "identityProviderMapper": "saml-user-attribute-idp-mapper",
            "config": {
                "attribute.name": "username",
                "user.attribute": "username"
            }
        }'
    
    # Email mapper
    curl -s -X POST "$keycloak_url/admin/realms/sp-realm/identity-provider/instances/saml-proxy/mappers" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "email-mapper",
            "identityProviderAlias": "saml-proxy",
            "identityProviderMapper": "saml-user-attribute-idp-mapper",
            "config": {
                "attribute.name": "email",
                "user.attribute": "email"
            }
        }'
    
    # First name mapper
    curl -s -X POST "$keycloak_url/admin/realms/sp-realm/identity-provider/instances/saml-proxy/mappers" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "firstName-mapper",
            "identityProviderAlias": "saml-proxy",
            "identityProviderMapper": "saml-user-attribute-idp-mapper",
            "config": {
                "attribute.name": "firstName",
                "user.attribute": "firstName"
            }
        }'
    
    # Last name mapper
    curl -s -X POST "$keycloak_url/admin/realms/sp-realm/identity-provider/instances/saml-proxy/mappers" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "lastName-mapper",
            "identityProviderAlias": "saml-proxy",
            "identityProviderMapper": "saml-user-attribute-idp-mapper",
            "config": {
                "attribute.name": "lastName",
                "user.attribute": "lastName"
            }
        }'
}

# Wait for services to be ready
wait_for_service() {
    local service_name=$1
    local url=$2
    local max_retries=30
    local retry_count=0
    
    log "Waiting for $service_name to be ready..."
    
    while [ $retry_count -lt $max_retries ]; do
        if curl -s --fail "$url" > /dev/null 2>&1; then
            log "$service_name is ready"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        warn "Waiting for $service_name... ($retry_count/$max_retries)"
        sleep 10
    done
    
    error "$service_name is not available after $max_retries attempts"
    return 1
}

main() {
    log "Starting Keycloak configuration..."
    
    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed. Please install jq first."
        exit 1
    fi
    
    # Wait for services
    wait_for_service "Keycloak SP" "$KEYCLOAK_SP_URL/realms/master"
    wait_for_service "Keycloak IdP" "$KEYCLOAK_IDP_URL/realms/master"
    wait_for_service "SAML Proxy" "$PROXY_URL/metadata"
    
    # Get access token
    log "Getting access token..."
    TOKEN=$(get_access_token "$KEYCLOAK_SP_URL")
    
    if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
        error "Failed to get access token"
        exit 1
    fi
    
    # Create SAML identity provider
    create_saml_idp "$TOKEN" "$KEYCLOAK_SP_URL"
    
    # Create identity provider mappers
    create_idp_mappers "$TOKEN" "$KEYCLOAK_SP_URL"
    
    log "Keycloak configuration completed successfully!"
    log "You can now test the SAML flow by accessing:"
    log "  - Keycloak SP: $KEYCLOAK_SP_URL/realms/sp-realm/account"
    log "  - SAML Proxy: $PROXY_URL"
}

# Run main function
main "$@"