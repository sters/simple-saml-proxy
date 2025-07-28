# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a lightweight and easy-to-use SAML proxy written in Go. **This is NOT a simple request/response proxy** that just forwards SAML messages. Instead, it's an intelligent intermediary that enables multi-tenant SSO capabilities for applications that only support single-tenant SSO.

### Core Concept

The proxy follows a **dual-role pattern**:
- **To Service Providers (SPs)**: Acts as an Identity Provider (IdP)
- **To Identity Providers (IdPs)**: Acts as a Service Provider (SP)

### Key Characteristics

1. **Zero External Infrastructure Dependencies**:
   - No database required
   - No persistent cache or storage
   - No configuration files
   - Single binary deployment
   - All configuration via environment variables

2. **Multi-IDP Support**:
   - Supports multiple Identity Providers simultaneously
   - Enables single-tenant SPs to work with multiple IDPs
   - Provides IDP selection interface during authentication

3. **Identity Federation Approach**:
   - Acts as an IDP to SPs but **does not store user accounts or identity information**
   - Does not perform identity federation or user data mapping
   - Simply relays authentication assertions between IDPs and SPs
   - Maintains session state only during the authentication flow

### Use Case

This proxy is designed for organizations that need to:
- Connect applications that only support single-tenant SSO to multiple Identity Providers
- Avoid complex identity federation systems when simple authentication relay is sufficient
- Deploy quickly without database setup or complex configuration management

## Development Commands

### Build and Run
```bash
make run              # Run the application
make run ARGS="..."   # Run with arguments
```

### Testing
```bash
make test            # Run unit tests with race detection
make cover           # Generate test coverage report
go test -v -run TestName ./...  # Run a specific test
```

### Linting
```bash
make lint            # Run golangci-lint
make lint-fix        # Run golangci-lint with auto-fix
```

### Dependencies
```bash
make tidy            # Clean up go.mod dependencies
```

## Architecture

The application is structured as a stateless HTTP server with modular SAML handling components.

### Core Components

1. **`/cmd/simple-saml-proxy/`**: Main application entry point
   - Initializes configuration from environment variables
   - Creates SAML providers and starts HTTP server

2. **`/proxy/`**: Core proxy implementation
   - `config.go`: Environment-based configuration structures
   - `proxy.go`: HTTP handlers and routing logic
   - `saml.go`: SAML provider creation and management
   - `storage.go`: In-memory storage for auth requests

### Key Flows

1. **SP-Initiated Flow**:
   - SP sends auth request to proxy's SSO endpoint
   - Proxy stores request and shows IdP selection page
   - User selects IdP, proxy redirects to chosen IdP
   - After IdP auth, proxy receives response at ACS endpoint
   - Proxy creates new assertion and sends to original SP

## Configuration

Configuration is loaded from environment variables:

- `PROXY_*`: Proxy settings (entity ID, URLs, certificates)
- `IDP_*`: Multiple IdP configurations (supports array)
- `SERVER_*`: Server settings (listen address)
- `PROXY_ALLOWED_SP_*`: Allowed service providers

### Key Environment Variables
- `PROXY_ENTITY_ID`: Proxy's SAML entity ID
- `PROXY_PRIVATE_KEY_PATH`: Path to private key
- `PROXY_CERTIFICATE_PATH`: Path to certificate
- `IDP_0_ID`, `IDP_1_ID`, etc.: IdP configurations
- `METADATA_MAX_RETRIES`: Max retry attempts for metadata fetching (default: 5)
- `METADATA_INITIAL_DELAY`: Initial retry delay (default: 1s)
- `METADATA_MAX_DELAY`: Maximum retry delay (default: 30s)
- `PROXY_REQUIRE_SIGNED_LOGOUT_REQUESTS`: Global setting for SLO signature validation (default: false)
- `PROXY_ALLOWED_SP_X_REQUIRE_SIGNED_LOGOUT_REQUESTS`: Per-SP SLO signature requirement

## Testing Approach

- Unit tests use `testing` package with table-driven tests
- E2E tests simulate full SAML flows with test certificates
- Test certificates are in `/e2e/` directory
- Use `httptest` for HTTP handler testing
- Mock SAML responses for IdP testing

## Linting Configuration

The project uses golangci-lint with all linters enabled except those listed in `.golangci.yml`. Common exclusions for test files include dupl, funlen, and paralleltest.

## Code Quality

The codebase is maintained with no TODO, FIXME, XXX, or HACK comments. All tasks and improvements are tracked through GitHub issues rather than inline comments.