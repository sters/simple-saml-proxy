# Simple SAML Proxy Docker Compose Example

This example demonstrates how to run the simple-saml-proxy with Docker Compose, connecting a SAML Service Provider (SP) to a SAML Identity Provider (IdP) through the proxy.

## Architecture

```
[Test SP] <--SAML--> [Simple SAML Proxy] <--SAML--> [Test IdP]
(port 8001)          (port 8080)                     (port 8000)
```

- **Test SP**: A SimpleSAMLphp instance configured as a Service Provider
- **Simple SAML Proxy**: Acts as an IdP to the SP and as an SP to the IdP
- **Test IdP**: A SimpleSAMLphp instance configured as an Identity Provider

## Quick Start

1. **Generate certificates** (required for SAML):
   ```bash
   cd docker/certs
   ./generate-certs.sh
   cd ../..
   ```

2. **Start all services**:
   ```bash
   docker-compose up --build
   ```

3. **Access the services**:
   - Service Provider: http://localhost:8001/simplesaml/
   - SAML Proxy: http://localhost:8080/
   - Identity Provider: http://localhost:8000/simplesaml/

## Testing the SAML Flow

### SP-Initiated SSO

1. Navigate to the SP admin interface: http://localhost:8001/simplesaml/
2. Log in with admin password: `admin123`
3. Go to "Authentication" → "Test configured authentication sources"
4. Select "default-sp"
5. You'll be redirected to the Simple SAML Proxy
6. Select "Test Identity Provider" from the IdP selection page
7. Log in with test credentials:
   - Username: `user1`
   - Password: `password`
8. You'll be redirected back to the SP with the authenticated user information

### Test Users

The IdP is configured with two test users:
- `user1` / `password` - Employee with email user1@example.com
- `user2` / `password` - Student with email user2@example.com

## Configuration Details

### Simple SAML Proxy

The proxy is configured through environment variables in `docker-compose.yml`:

- **Entity ID**: `http://simple-saml-proxy:8080`
- **SSO URL**: `http://simple-saml-proxy:8080/sso`
- **ACS URL**: `http://simple-saml-proxy:8080/acs`
- **Metadata URL**: `http://simple-saml-proxy:8080/metadata`

### Identity Provider Configuration

The proxy is configured to connect to one IdP:
- **ID**: `test-idp`
- **Name**: Test Identity Provider
- **SSO URL**: `http://test-idp:8000/simplesaml/saml2/idp/SSOService.php`
- **Metadata URL**: `http://test-idp:8000/simplesaml/saml2/idp/metadata.php`

### Allowed Service Providers

The proxy is configured to allow one SP:
- **Entity ID**: `http://test-sp:8001`
- **Name**: Test Service Provider
- **ACS URL**: `http://test-sp:8001/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp`

## Directory Structure

```
example/
├── docker-compose.yml      # Docker Compose configuration
├── Dockerfile             # Dockerfile for simple-saml-proxy
├── README.md             # This file
└── docker/
    ├── certs/            # SAML certificates
    │   ├── generate-certs.sh
    │   ├── proxy.crt     # (generated)
    │   ├── proxy.key     # (generated)
    │   ├── idp.crt       # (generated)
    │   ├── idp.key       # (generated)
    │   ├── sp.crt        # (generated)
    │   └── sp.key        # (generated)
    ├── idp/              # IdP configuration
    │   ├── authsources.php
    │   └── saml20-sp-hosted.php
    └── sp/               # SP configuration
        ├── authsources.php
        └── saml20-idp-hosted.php
```

## Adding More IdPs or SPs

### To add another IdP:

1. Add IdP configuration to the proxy's environment variables:
   ```yaml
   - IDP_1_ID=another-idp
   - IDP_1_NAME=Another Identity Provider
   - IDP_1_SSO_URL=http://another-idp:8002/sso
   - IDP_1_METADATA_URL=http://another-idp:8002/metadata
   ```

2. Add the IdP service to `docker-compose.yml`

### To add another allowed SP:

1. Add SP configuration to the proxy's environment variables:
   ```yaml
   - PROXY_ALLOWED_SP_1_ENTITY_ID=http://another-sp:8003
   - PROXY_ALLOWED_SP_1_NAME=Another Service Provider
   - PROXY_ALLOWED_SP_1_ACS_URL=http://another-sp:8003/acs
   ```

2. Add the SP service to `docker-compose.yml`

## Troubleshooting

### Certificate Issues
If you encounter certificate validation errors:
1. Ensure certificates are generated: `ls docker/certs/*.crt`
2. Regenerate if needed: `cd docker/certs && ./generate-certs.sh`

### Connection Issues
- Check all services are running: `docker-compose ps`
- View logs: `docker-compose logs -f [service-name]`
- Ensure ports 8000, 8001, and 8080 are not in use

### SAML Errors
- Check proxy logs: `docker-compose logs -f simple-saml-proxy`
- Verify metadata is accessible:
  - Proxy: http://localhost:8080/metadata
  - IdP: http://localhost:8000/simplesaml/saml2/idp/metadata.php

## Security Note

This example uses self-signed certificates and simple passwords for demonstration purposes only. In production:
- Use properly signed certificates
- Configure strong passwords
- Use HTTPS for all endpoints
- Implement proper session management
- Review and harden all security settings