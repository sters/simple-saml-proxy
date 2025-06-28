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

Simple SAML Proxy acts as a Service Provider (SP) that can authenticate users against an Identity Provider (IdP).

### Configuration

The application is configured using environment variables:

#### Proxy SP Settings
- `PROXY_ENTITY_ID` - Entity ID for the proxy SP (default: "http://localhost:8080/metadata")
- `PROXY_ACS_URL` - Assertion Consumer Service URL (default: "http://localhost:8080/sso/acs")
- `PROXY_METADATA_URL` - Metadata URL (default: "http://localhost:8080/metadata")
- `PROXY_PRIVATE_KEY_PATH` - Path to the private key file (required)
- `PROXY_CERTIFICATE_PATH` - Path to the certificate file (required)

#### IdP Settings
- `IDP_ENTITY_ID` - Entity ID for the upstream IdP
- `IDP_SSO_URL` - Single Sign-On URL for the upstream IdP
- `IDP_CERTIFICATE_PATH` - Path to the IdP's certificate file

#### Server Settings
- `SERVER_LISTEN_ADDRESS` - Address and port to listen on (default: ":8080")

### Endpoints

- `/metadata` - SAML metadata endpoint
- `/sso` - Single Sign-On initiation endpoint
- `/sso/acs` - Assertion Consumer Service endpoint
- `/ping` - Health check endpoint

### Example Usage

1. Generate certificates for the SP:
   ```shell
   openssl req -x509 -newkey rsa:2048 -keyout proxy.key -out proxy.crt -days 365 -nodes
   ```

2. Set environment variables:
   ```shell
   export PROXY_PRIVATE_KEY_PATH=./proxy.key
   export PROXY_CERTIFICATE_PATH=./proxy.crt
   export IDP_ENTITY_ID=https://idp.example.com/saml/metadata
   export IDP_SSO_URL=https://idp.example.com/saml/sso
   export IDP_CERTIFICATE_PATH=./idp.crt
   ```

3. Run the proxy:
   ```shell
   simple-saml-proxy
   ```

4. Access the metadata at http://localhost:8080/metadata

5. To initiate authentication, redirect users to http://localhost:8080/sso

### Integration with IdPs

1. Register the SP with your IdP using the metadata URL (http://localhost:8080/metadata)
2. Configure the IdP to send responses to the ACS URL (http://localhost:8080/sso/acs)
3. Obtain the IdP's metadata or certificate and configure the proxy with it
