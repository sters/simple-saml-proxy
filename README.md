# simple-saml-proxy

[![go](https://github.com/sters/simple-saml-proxy/workflows/Go/badge.svg)](https://github.com/sters/simple-saml-proxy/actions?query=workflow%3AGo)
[![codecov](https://codecov.io/gh/sters/simple-saml-proxy/branch/main/graph/badge.svg)](https://codecov.io/gh/sters/simple-saml-proxy)
[![go-report](https://goreportcard.com/badge/github.com/sters/simple-saml-proxy)](https://goreportcard.com/report/github.com/sters/simple-saml-proxy)

## Install

```shell
go install github.com/sters/simple-saml-proxy@latest
```

or use specific version from [Releases](https://github.com/sters/simple-saml-proxy/releases).

## Usage

Simple SAML Proxy acts as a SAML Identity Provider (IdP) proxy:
- To Service Providers (SPs), it appears as an IdP
- To Identity Providers (IdPs), it appears as an SP

This allows for a centralized authentication flow where:
1. Users access a Service Provider (SP)
2. SP redirects to this proxy for authentication
3. User selects an Identity Provider (IdP) on the proxy's selection page
4. User is redirected to the selected IdP for authentication
5. After authentication, user is redirected back to the proxy
6. Proxy forwards the authentication response to the original SP

Note: IdP-Initiated flow is not yet implemented.

### Configuration

The application is configured using environment variables:

#### Proxy SP Settings
- `PROXY_ENTITY_ID` - Entity ID for the proxy SP (default: "SimpleSamlProxy")
- `PROXY_ACS_URL` - Assertion Consumer Service URL (default: "http://localhost:8080/sso/acs")
- `PROXY_METADATA_URL` - Metadata URL (default: "http://localhost:8080/metadata")
- `PROXY_PRIVATE_KEY_PATH` - Path to the private key file (required)
- `PROXY_CERTIFICATE_PATH` - Path to the certificate file (required)

#### IdP Settings
You can configure multiple IdPs using environment variables with indexed suffixes:
- For the first IdP
  - `IDP_0_ID` - Unique identifier (it should not use sequential number)
  - `IDP_0_ENTITY_ID` - Entity ID
  - `IDP_0_SSO_URL` - Single Sign-On URL
  - `IDP_0_CERTIFICATE_PATH` - Path to the certificate file
- For the second IdP
  - `IDP_1_ID` - Unique identifier (it should not use sequential number)
  - `IDP_1_ENTITY_ID` - Entity ID
  - `IDP_1_SSO_URL` - Single Sign-On URL
  - `IDP_1_CERTIFICATE_PATH` - Path to the certificate file

And so on for additional IdPs.

#### Server Settings
- `SERVER_LISTEN_ADDRESS` - Address and port to listen on (default: ":8080")

### Endpoints

#### For Service Providers (SPs)
- `/metadata` - SAML metadata endpoint (proxy acts as IdP)
- `/sso` - Single Sign-On endpoint where SPs send AuthnRequests (shows IdP selection page)

#### For Identity Providers (IdPs)
- `/sso/acs` - Assertion Consumer Service endpoint where IdPs send SAML responses

#### IdP Selection
- `/select_idp/{idp_id}?SAMLRequest={saml_request}&RelayState={relay_state}` - Endpoint to select an IdP and forward the SAML request

#### Legacy Endpoints (for backward compatibility)
- `/link_sso/{idp_id}?service={service_url}` - Legacy endpoint to select an IdP and set a cookie, then redirect to the service URL

#### Other Endpoints
- `/ping` - Health check endpoint
- `/idp-initiated` - IdP-Initiated flow endpoint (not yet implemented)

### Example Usage

1. Generate certificates for the SP:
   ```shell
   openssl req -x509 -newkey rsa:2048 -keyout proxy.key -out proxy.crt -days 365 -nodes
   ```

2. Set environment variables:

   ```shell
   export PROXY_PRIVATE_KEY_PATH=./proxy.key
   export PROXY_CERTIFICATE_PATH=./proxy.crt

   # First IdP
   export IDP_0_ID=example1
   export IDP_0_ENTITY_ID=https://idp1.example.com/saml/metadata
   export IDP_0_SSO_URL=https://idp1.example.com/saml/sso
   export IDP_0_CERTIFICATE_PATH=./idp1.crt

   # Second IdP
   export IDP_1_ID=example2
   export IDP_1_ENTITY_ID=https://idp2.example.com/saml/metadata
   export IDP_1_SSO_URL=https://idp2.example.com/saml/sso
   export IDP_1_CERTIFICATE_PATH=./idp2.crt
   ```

3. Run the proxy:
   ```shell
   simple-saml-proxy
   ```

4. Access the metadata at http://localhost:8080/metadata

5. To initiate authentication (SP-Initiated flow):
   1. Configure your SP to use the proxy as an IdP (using the metadata at http://localhost:8080/metadata)
   2. When a user accesses your SP, it will redirect them to the proxy's SSO endpoint (http://localhost:8080/sso)
   3. The proxy will show an IdP selection page where the user can choose which IdP to use
   4. After selecting an IdP, the user will be redirected to that IdP for authentication
   5. After successful authentication, the IdP will redirect the user back to the proxy
   6. The proxy will process the SAML response and forward it to your SP
   7. Your SP will receive the authentication information and grant access to the user

   Note: The legacy flow using `/link_sso/{idp_id}?service=http://your-service.com` is still supported for backward compatibility.

### Integration

#### Integration with Service Providers (SPs)
1. Configure your SP to use the proxy as an IdP
2. Use the proxy's metadata URL (http://localhost:8080/metadata) to configure your SP
3. Set your SP to send AuthnRequests to the proxy's SSO URL (http://localhost:8080/sso)

#### Integration with Identity Providers (IdPs)
1. Register the proxy as an SP with your IdP
2. Use the proxy's entity ID in the IdP configuration
3. Configure the IdP to send responses to the proxy's ACS URL (http://localhost:8080/sso/acs)
4. Obtain the IdP's metadata or certificate and configure the proxy with it
