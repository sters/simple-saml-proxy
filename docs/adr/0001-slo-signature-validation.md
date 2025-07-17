# ADR-0001: SAML Single Logout (SLO) Request Signature Validation

## Status

Proposed

## Context

The simple-saml-proxy currently accepts Single Logout (SLO) requests from Service Providers without validating signatures. This is tracked in GitHub issue #27. The current implementation (in `proxy/proxy_handler_slo.go:65`) includes a warning comment and logs when signed logout requests are received but does not validate them.

### Current State

- The proxy accepts both signed and unsigned logout requests
- When a logout request includes a signature, it logs a warning but proceeds without validation
- Regular SAML authentication responses ARE validated using the crewjam/saml library's `ParseResponse` method
- The HTTP-Redirect binding (commonly used for logout) often uses unsigned requests, but the SAML 2.0 specification recommends signature validation for security

### Security Implications

Without signature validation on logout requests:
1. **Logout CSRF attacks**: Malicious actors could forge logout requests to terminate user sessions
2. **Session hijacking**: Attackers could selectively log out specific users
3. **Compliance issues**: Many security frameworks require signature validation on all SAML messages

## Decision

Implement signature validation for SAML Single Logout requests while maintaining backward compatibility with unsigned requests through configuration.

## Implementation Plan

### Phase 1: Core Signature Validation (Priority: High)

1. **Add signature validation logic**
   - Create `validateLogoutRequestSignature` function in `proxy/proxy_handler_slo.go`
   - Use the crewjam/saml library's existing signature validation capabilities
   - Validate against the SP's configured certificate

2. **Configuration support**
   - Add per-SP configuration: `PROXY_ALLOWED_SP_X_REQUIRE_SIGNED_LOGOUT_REQUESTS` (default: false)
   - Add global configuration: `PROXY_REQUIRE_SIGNED_LOGOUT_REQUESTS` (default: false)
   - SP-specific settings override global settings

3. **Error handling**
   - Return HTTP 400 Bad Request for invalid signatures when validation is required
   - Log detailed errors for debugging while returning generic errors to clients
   - Continue to accept unsigned requests when signature validation is not required

### Phase 2: HTTP-Redirect Binding Support (Priority: High)

1. **Query parameter signature validation**
   - Implement validation for signatures passed as query parameters (SigAlg, Signature)
   - Handle URL encoding/decoding properly
   - Support both RSA-SHA256 and RSA-SHA1 (with deprecation warning for SHA1)

2. **Signature generation for proxy-initiated logouts**
   - When proxy forwards logout to upstream IdP, sign the request
   - Use the proxy's private key for signing
   - Include RelayState in signature calculation when present

### Phase 3: Enhanced Security Features (Priority: Medium)

1. **Certificate management**
   - Support multiple certificates per SP for key rotation
   - Validate certificate validity periods
   - Add certificate fingerprint validation option

2. **Signature algorithm configuration**
   - Make supported algorithms configurable
   - Default to SHA256, allow SHA1 for backward compatibility
   - Log warnings for weak algorithms

3. **Audit logging**
   - Log all logout attempts with signature validation results
   - Include request details for security analysis
   - Separate security events from operational logs

### Phase 4: Testing and Documentation (Priority: High)

1. **Unit tests**
   - Test signature validation with valid/invalid signatures
   - Test configuration permutations
   - Test error handling paths

2. **Integration tests**
   - Add E2E tests for signed logout flows
   - Test with multiple IdP/SP combinations
   - Verify backward compatibility

3. **Documentation updates**
   - Update SAML specification support documentation
   - Add configuration examples
   - Document security best practices

## Technical Details

### Signature Validation Algorithm

```go
func validateLogoutRequestSignature(
    logoutRequest *crewjamsaml.LogoutRequest,
    sp *saml.ServiceProvider,
    rawQuery string,
) error {
    // For HTTP-Redirect binding with query parameters
    if logoutRequest.Signature == nil && rawQuery != "" {
        return validateRedirectSignature(rawQuery, sp)
    }
    
    // For HTTP-POST binding with embedded signature
    if logoutRequest.Signature != nil {
        return validateEmbeddedSignature(logoutRequest, sp)
    }
    
    return nil // No signature present
}
```

### Configuration Structure

```go
type SPConfig struct {
    // Existing fields...
    RequireSignedLogoutRequests bool
    AcceptedSignatureAlgorithms []string
}
```

### Backward Compatibility

- Default configuration accepts unsigned requests
- Existing deployments continue to work without changes
- Migration path through gradual configuration updates
- Warning logs for unsigned requests when moving to signed-only mode

## Consequences

### Positive

- **Enhanced security**: Prevents logout request forgery and CSRF attacks
- **Standards compliance**: Aligns with SAML 2.0 security best practices
- **Configurable security**: Allows gradual migration to stricter security
- **Audit trail**: Better visibility into logout operations

### Negative

- **Configuration complexity**: Additional per-SP configuration required
- **Breaking change risk**: Misconfiguration could block legitimate logouts
- **Performance impact**: Minimal CPU overhead for signature validation
- **Compatibility concerns**: Some SPs may not support signed logout requests

## Alternatives Considered

1. **Mandatory signature validation**
   - Rejected: Would break backward compatibility
   - Many existing SPs don't sign logout requests

2. **Session-based validation only**
   - Rejected: Doesn't protect against session hijacking
   - Doesn't meet security compliance requirements

3. **Custom signature format**
   - Rejected: Would break SAML standard compliance
   - Would require custom SP implementations

## References

- [SAML 2.0 Security Considerations](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)
- [SAML 2.0 Bindings Specification](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [crewjam/saml library documentation](https://github.com/crewjam/saml)
- GitHub Issue #27: Implement SLO signature validation

## Migration Guide

### Phase 1: Monitoring (1-2 weeks)
1. Deploy with signature validation disabled
2. Monitor logs for unsigned logout requests
3. Identify SPs that need to enable signing

### Phase 2: SP Configuration (2-4 weeks)
1. Work with SP administrators to enable request signing
2. Test signed logout flows in staging environment
3. Enable signature requirement per SP as they're ready

### Phase 3: Enforcement (4+ weeks)
1. Enable global signature requirement with per-SP exceptions
2. Monitor for any failed logout attempts
3. Complete migration for remaining SPs

### Rollback Plan
1. Disable signature validation via configuration
2. No code changes required
3. Instant restoration of previous behavior