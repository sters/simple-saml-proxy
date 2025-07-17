# SAML 2.0 Specification Support

This document details the level of SAML 2.0 specification support implemented in simple-saml-proxy.

**Last Updated**: 2025-07-11

## Overview

simple-saml-proxy implements a subset of the SAML 2.0 specification, focusing on the Web Browser SSO Profile for multi-IdP federation. The proxy acts as both an Identity Provider (IdP) to Service Providers and a Service Provider (SP) to upstream Identity Providers.

## Support Status Legend

- ✅ **Fully Supported**: Feature is completely implemented and tested
- ⚠️ **Partially Supported**: Basic functionality exists but with limitations
- ❌ **Not Supported**: Feature is not implemented
- 🚧 **Planned**: Feature is planned for future implementation

## SAML 2.0 Core Specifications

### 1. SAML Bindings

| Binding | Status | Notes |
|---------|--------|-------|
| HTTP-Redirect | ✅ | Used for authentication requests to IdPs |
| HTTP-POST | ✅ | Used for receiving SAML responses |
| HTTP-Artifact | ❌ | Not implemented |
| SOAP | ❌ | Not implemented |
| PAOS | ❌ | Not implemented |
| HTTP-URI | ❌ | Not implemented |

### 2. SAML Profiles

| Profile | Status | Notes |
|---------|--------|-------|
| Web Browser SSO | ✅ | Core functionality of the proxy |
| Single Logout | ⚠️ | Partial implementation with signature validation (2025-01-17) |
| Enhanced Client/Proxy (ECP) | ❌ | Not implemented |
| Identity Provider Discovery | ❌ | Custom IdP selection implemented instead |
| Name Identifier Management | ❌ | Not implemented |
| Artifact Resolution | ❌ | Not implemented |
| Assertion Query/Request | ❌ | Not implemented |

### 3. SAML Assertions

| Feature | Status | Notes |
|---------|--------|-------|
| Basic Assertions | ✅ | Creation and parsing supported |
| Subject | ✅ | With NameID |
| Conditions | ✅ | NotBefore, NotOnOrAfter, AudienceRestriction |
| AuthnStatement | ✅ | Full support with AuthnInstant |
| AttributeStatement | ✅ | Configurable attributes |
| AuthzDecisionStatement | ❌ | Not implemented |

### 4. Security Features

| Feature | Status | Notes |
|---------|--------|-------|
| XML Signatures | ✅ | Full support with RSA-SHA256 (implemented 2025-07-11) |
| Signature Validation | ✅ | Automatic validation with X.509 certificates |
| SLO Signature Validation | ⚠️ | HTTP-Redirect binding framework (2025-01-17), SP cert retrieval pending |
| SLO Signature Generation | ✅ | Full implementation for proxy-initiated logouts |
| Assertion Encryption | ❌ | Not supported |
| Attribute Encryption | ❌ | Not supported |
| TLS/HTTPS | ✅ | Recommended for deployment |

### 5. SAML Metadata

| Feature | Status | Notes |
|---------|--------|-------|
| Metadata Generation | ✅ | Available at `/metadata` endpoint |
| Metadata Consumption | ✅ | From URLs or manual configuration |
| Metadata Validation | ⚠️ | Basic validation only |
| Metadata Refresh | ❌ | Manual restart required |
| EntitiesDescriptor | ❌ | Single entity only |

### 6. Name Identifier Formats

| Format | Status | Notes |
|---------|--------|-------|
| Unspecified | ⚠️ | Default behavior |
| emailAddress | ⚠️ | Not explicitly validated |
| X509SubjectName | ❌ | Not supported |
| WindowsDomainQualifiedName | ❌ | Not supported |
| Kerberos | ❌ | Not supported |
| entity | ❌ | Not supported |
| persistent | ⚠️ | Passed through but not managed |
| transient | ⚠️ | Passed through but not managed |

### 7. Authentication Context

| Feature | Status | Notes |
|---------|--------|-------|
| AuthnContextClassRef | ❌ | Not implemented |
| AuthnContextDeclRef | ❌ | Not implemented |
| RequestedAuthnContext | ❌ | Not implemented |
| Comparison operators | ❌ | Not implemented |

### 8. Request/Response Features

| Feature | Status | Notes |
|---------|--------|-------|
| AuthnRequest | ✅ | Full support |
| Response | ✅ | Full support |
| LogoutRequest | ⚠️ | Receiving and validating signatures (2025-01-17) |
| LogoutResponse | ⚠️ | Basic support for SLO flows |
| ArtifactResolve | ❌ | Not implemented |
| ArtifactResponse | ❌ | Not implemented |
| ManageNameIDRequest | ❌ | Not implemented |
| ManageNameIDResponse | ❌ | Not implemented |
| AssertionIDRequest | ❌ | Not implemented |
| NameIDMappingRequest | ❌ | Not implemented |
| NameIDMappingResponse | ❌ | Not implemented |
| AttributeQuery | ❌ | Not implemented |
| AuthnQuery | ❌ | Not implemented |
| AuthzDecisionQuery | ❌ | Not implemented |

### 9. SSO Features

| Feature | Status | Notes |
|---------|--------|-------|
| SP-Initiated SSO | ✅ | Primary use case |
| IdP-Initiated SSO | ✅ | Full support with SP selection |
| Multi-IdP Support | ✅ | Core feature with selection UI |
| Multi-SP Support | ✅ | Configurable allowed SPs |
| ForceAuthn | ❌ | Not implemented |
| IsPassive | ❌ | Not implemented |
| AssertionConsumerServiceIndex | ❌ | Not implemented |
| AttributeConsumingServiceIndex | ❌ | Not implemented |
| ProviderName | ⚠️ | Basic support |

### 10. Session Management

| Feature | Status | Notes |
|---------|--------|-------|
| Session Tracking | ⚠️ | Cookie-based only |
| Session Timeout | ❌ | No timeout handling |
| Single Logout | ⚠️ | Partial implementation with signature validation |
| Session Synchronization | ❌ | Not implemented |

## Attribute Support

### Standard Attributes

The proxy supports passing through any attributes from the upstream IdP, with special handling for:

- `UserID`
- `Username`
- `Email`
- `FullName`
- `GivenName`
- `Surname`

Custom attributes can be configured and will be passed through as-is.

## Implementation Details

### Libraries Used

1. **github.com/zitadel/saml** (v0.3.5)
   - Used for IdP-side functionality
   - Handles metadata generation and SAML response creation
   - Provides XML signature generation via amdonov/xmlsig

2. **github.com/crewjam/saml** (v0.5.1)
   - Used for SP-side functionality
   - Handles SAML request parsing and response validation
   - Provides signature validation via russellhaering/goxmldsig

### Architecture

The proxy implements a dual-role architecture:
- **As an IdP**: Presents a single IdP interface to downstream Service Providers
- **As an SP**: Acts as a Service Provider to upstream Identity Providers

### Storage

- **In-memory storage**: Authentication requests and SP configurations
- **No persistent storage**: All state is ephemeral
- **Cookie-based sessions**: For tracking authentication flows

## Compliance Notes

### SAML 2.0 Conformance

This implementation provides:
- ✅ **Web Browser SSO Profile conformance** for basic scenarios
- ⚠️ **Partial metadata conformance** (generation and consumption)
- ❌ **No conformance** for Single Logout, ECP, or other advanced profiles

### Security Considerations

1. **HTTPS Required**: The proxy should always be deployed with TLS
2. **No Encryption**: Assertions and attributes are not encrypted
3. **Signature Validation**: Full XML digital signature validation with certificate chain support
4. **SLO Signature Validation**: Configurable per-SP with support for HTTP-Redirect binding
5. **Replay Protection**: Time-based validation and request ID tracking for SLO

### Limitations

1. **No persistent sessions**: Restart loses all session data
2. **Partial logout support**: SLO signature validation only, full flow not complete
3. **Limited attribute mapping**: No transformation capabilities
4. **No encryption support**: Assertions and attributes are not encrypted
5. **SLO HTTP-POST binding**: Embedded signature validation not yet implemented

## Use Cases

This proxy is suitable for:
- ✅ Federating multiple IdPs to present a single IdP interface
- ✅ Basic enterprise SSO scenarios
- ✅ Development and testing of SAML integrations
- ⚠️ Production use with understanding of limitations
- ❌ High-security environments requiring encryption
- ❌ Scenarios requiring Single Logout
- ❌ Complex attribute transformation requirements

## Future Considerations

Potential enhancements could include:
- 🚧 Single Logout (SLO) support
- 🚧 Assertion encryption
- 🚧 Persistent session storage
- 🚧 AuthnContext support
- 🚧 Enhanced attribute mapping
- 🚧 SAML 2.0 full conformance

## Recent Improvements (2025)

- **2025-01-17**: Implemented SLO signature validation for HTTP-Redirect binding (ADR-0001)
- **2025-01-17**: Added configurable signature requirements per SP
- **2025-01-17**: Implemented signature generation for proxy-initiated logout requests
- **2025-07-11**: Implemented full XML digital signature support with RSA-SHA256
- **2025-07-11**: Enhanced E2E testing with proper signature validation
- **2025-07-10**: Improved IdP-initiated SSO flow with SP selection
- **2025-07-10**: Added comprehensive test coverage for all SAML flows

## References

- [SAML 2.0 Core Specification](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [SAML 2.0 Bindings](http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [SAML 2.0 Profiles](http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [SAML 2.0 Metadata](http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)