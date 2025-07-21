# Simple SAML Proxy - Integration Testing

This directory contains the integration testing setup for the Simple SAML Proxy project, implementing the solution designed in [Issue #26](https://github.com/sters/simple-saml-proxy/issues/26).

## Architecture

The integration testing environment uses a **Multi-Keycloak** setup to test the proxy's IDP selection functionality:

- **Keycloak IdP** (port 8080): Acts as the first Identity Provider ("Development IdP") with test users
- **Keycloak IdP2** (port 8083): Acts as the second Identity Provider ("Enterprise IdP") with enterprise users
- **Keycloak SP** (port 8081): Acts as the Service Provider consuming authentication
- **Simple SAML Proxy** (port 8082): The proxy being tested, bridges multiple IDPs and SP

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Make (optional, for easier commands)

### Setup and Run

```bash
# Generate certificates and start all services
make dev-setup

# Or manually:
make setup      # Generate certificates
make start      # Start all services
make configure  # Configure Keycloak SP with SAML Identity Provider
make test       # Run integration tests
```

### Access Points

- **Keycloak IdP Admin**: http://localhost:8080/admin (admin/admin)
- **Keycloak IdP2 Admin**: http://localhost:8083/admin (admin/admin)
- **Keycloak SP Admin**: http://localhost:8081/admin (admin/admin)
- **SAML Proxy**: http://localhost:8082

### Test Users

#### Development IdP (port 8080)
- **testuser/testpassword** - Standard test user

#### Enterprise IdP (port 8083)
- **enterpriseuser/enterprisepassword** - Enterprise user
- **testuser/testpassword** - Test user (IDP2 variant)

## Testing

### IDP Selection Screen Testing

With the multi-IDP setup, you can now test the proxy's IDP selection functionality:

1. **Start the environment**: `make dev-setup`
2. **Access Keycloak SP**: http://localhost:8081
3. **Initiate SAML login** through the SP's SAML broker
4. **Observe IDP selection screen** at the proxy (should show "Development IdP" and "Enterprise IdP")
5. **Test different IDPs** by selecting each option and logging in with respective users

### End-to-End Tests (Playwright)

```bash
# Run all tests
make test-e2e

# Run specific test suites
cd tests
npm run test:flow           # Run simplified SAML flow tests
npm run test:proxy          # Run detailed proxy flow tests

# Run with different modes
npm run test:verbose        # Verbose output
npm run test:headed         # Run in headed browser
npm run test:ui            # Run with Playwright UI
npm run test:debug         # Run in debug mode
```

### SAML Proxy Flow Testing

The tests validate the complete SAML proxy flow:
```
SP →[SAML AuthnRequest]→ Proxy →[New SAML AuthnRequest]→ IdP →[SAML Response]→ Proxy →[New SAML Response]→ SP
```

Key test files:
- `tests/saml-flow.spec.js` - Simplified flow tests
- `tests/saml-proxy-flow.spec.js` - Detailed proxy flow validation

### Verbose Mode Features

When running tests in verbose mode, you get:

- **Detailed HTTP traffic**: All requests/responses with headers and status codes
- **SAML message inspection**: Base64 encoded/decoded SAML requests
- **Step-by-step logging**: Each action in the flow is logged
- **Response content**: First N characters of responses for debugging
- **Network timing**: Time taken for each request
- **Browser console logs**: JavaScript errors and console messages
- **Screenshots/videos**: Automatic capture in verbose mode (Playwright)
- **HAR recording**: Full network traffic recording (Playwright)

## Project Structure

```
example/
├── docker-compose.yml          # Main orchestration file
├── Dockerfile                  # Simple SAML Proxy container
├── Makefile                    # Automation commands
├── README.md                   # This file
├── certs/                      # Test certificates
│   ├── generate-certs.sh       # Certificate generation
│   ├── proxy.crt/key          # Proxy certificates
│   ├── keycloak-idp.crt/key   # IdP certificates
│   └── keycloak-sp.crt/key    # SP certificates
├── keycloak-idp/              # Keycloak IdP configuration
│   └── test-realm.json        # Test realm with users
├── keycloak-sp/               # Keycloak SP configuration
│   └── test-realm.json        # Test realm with IdP config
├── scripts/                   # Configuration scripts
│   └── configure-keycloak.sh  # Post-startup Keycloak configuration
└── tests/                     # Playwright E2E tests
    ├── package.json
    ├── playwright.config.js
    └── tests/
        └── saml-flow.spec.js          # Comprehensive SAML flow tests
```

## Configuration

### Environment Variables

The Simple SAML Proxy is configured via environment variables in `docker-compose.yml`:

```yaml
# Proxy configuration
PROXY_ENTITY_ID: "http://localhost:8082/metadata"
PROXY_ACS_URL: "http://localhost:8082/acs"
PROXY_SSO_URL: "http://localhost:8082/sso"

# IdP configuration (Multiple IDPs)
IDP_0_ID: "keycloak-idp"
IDP_0_NAME: "Development IdP"
IDP_0_METADATA_URL: "http://keycloak-idp:8080/realms/test/protocol/saml/descriptor"

IDP_1_ID: "keycloak-idp2"
IDP_1_NAME: "Enterprise IdP"
IDP_1_METADATA_URL: "http://keycloak-idp2:8083/realms/test2/protocol/saml/descriptor"

# SP configuration
PROXY_ALLOWED_SP_0_ENTITY_ID: "http://keycloak-sp:8080/realms/test"
PROXY_ALLOWED_SP_0_ACS_URL: "http://keycloak-sp:8080/realms/test/broker/saml/endpoint"

# SLO Signature Validation (optional, default: false)
PROXY_REQUIRE_SIGNED_LOGOUT_REQUESTS: "false"  # Global setting
PROXY_ALLOWED_SP_0_REQUIRE_SIGNED_LOGOUT_REQUESTS: "false"  # Per-SP setting
```

### Keycloak Configuration

- **IdP Realm**: Contains test users and SAML client configuration
- **SP Realm**: Contains SAML identity provider configuration pointing to the proxy

## Development Workflow

### Common Commands

```bash
# Start development environment
make dev-setup

# View logs
make logs           # All services
make logs-proxy     # Proxy only
make logs-idp       # IdP only
make logs-sp        # SP only

# Get shell access
make shell-proxy    # Proxy container
make shell-idp      # IdP container
make shell-sp       # SP container

# Clean up
make clean          # Stop and remove volumes
make stop           # Stop services only
```

### Testing Workflow

1. **Start Services**: `make start`
2. **Configure Keycloak**: `make configure`
3. **Run E2E Tests**: `make test-e2e`
4. **Check Logs**: `make logs`
5. **Clean Up**: `make clean`

## Troubleshooting

### Common Issues

1. **Services not starting**: Check if ports 8080, 8081, 8082 are available
2. **Certificate errors**: Regenerate certificates with `make setup`
3. **Network issues**: Ensure Docker daemon is running
4. **Test failures**: Check service logs with `make logs`

### Debugging

```bash
# Check service status
make status

# Follow logs in real-time
make logs

# Access container directly
make shell-proxy
```

## Implementation Notes

This setup was designed based on the requirements and discussion in [Issue #26](https://github.com/sters/simple-saml-proxy/issues/26):

- **Free OSS Solution**: Uses Keycloak (Apache 2.0 license)
- **Production-Ready**: Keycloak provides enterprise-grade SAML support
- **Docker-Based**: Easy local development and CI/CD integration
- **Consistent Technology**: Same technology stack for both IdP and SP
- **Extensible**: Easy to add more test scenarios and configurations

## Recent Improvements

The example setup has been optimized to reduce code duplication and improve maintainability:

### Configuration Consolidation
- **Docker Compose**: Reduced ~50 lines by using YAML anchors for shared Keycloak configuration
- **Certificate Generation**: Refactored to use functions, reducing ~15 lines of duplicate code
- **SAML Decoding**: Merged duplicate Python scripts into one flexible tool with `--simple` flag

### Development Tools
- **Unified SAML Decoder**: `decode-saml.py` now supports both XML and regex parsing modes
- **Validation Script**: Added `validate-setup.sh` to verify configuration integrity
- **Streamlined Package Scripts**: Cleaned up npm test scripts in `package.json`

### Benefits
- **Reduced Maintenance**: Common configurations are centralized
- **Improved Consistency**: Shared templates ensure uniform behavior
- **Better Documentation**: Consolidated tools with clear usage instructions

## Contributing

When adding new tests:

1. Add E2E tests to `tests/tests/`
2. Use verbose mode for debugging: `VERBOSE=true npm test`
3. Update Makefile if needed
4. Update this README with new instructions
5. Run `bash validate-setup.sh` to ensure changes don't break setup

## License

This testing setup follows the same license as the main project.