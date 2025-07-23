# IdP-Initiated SAML Flow Support

This document describes the IdP-initiated SAML flow support in simple-saml-proxy.

## Overview

IdP-initiated flow is a SAML authentication pattern where the user starts at the Identity Provider (IdP) rather than the Service Provider (SP). In this flow:

1. User logs in directly at the IdP
2. IdP sends an unsolicited SAML response to the proxy
3. Proxy shows SP selection (if multiple SPs are configured)
4. User is authenticated at the selected SP

## Implementation Details

### Flow Detection

The proxy detects IdP-initiated flow by checking for the absence of expected cookies when a SAML response arrives at the `/acs` endpoint:

```go
// In handleSAMLACS
authRequestIDCookie, err := r.Cookie(cookieNameAuthRequestID)
isIDPInitiated := err == http.ErrNoCookie
```

### Request Processing

When an IdP-initiated flow is detected:

1. **Response Parsing**: The proxy attempts to parse the SAML response with each configured IdP provider
2. **Session Creation**: A temporary auth request is created with the assertion data
3. **SP Selection**: 
   - Single SP: Automatic redirect
   - Multiple SPs: Selection page is shown

### Key Components

#### Handler Functions

- `handleIDPInitiatedFlow()`: Main handler for IdP-initiated responses
- `handleSPSelect()`: Shows SP selection page
- `handleSPSelected()`: Processes SP selection
- `redirectToSPWithAssertion()`: Creates SAML response for selected SP

#### Endpoints

- `/acs`: Accepts both SP-initiated and IdP-initiated SAML responses
- `/sp_select`: SP selection page for IdP-initiated flow
- `/sp_selected`: Processes SP selection

## Configuration

### Keycloak IdP Configuration

To enable IdP-initiated SSO in Keycloak, add the following attributes to your SAML client:

```json
{
  "attributes": {
    "saml_idp_initiated_sso_url_name": "saml-proxy",
    "saml_idp_initiated_sso_relay_state": ""
  }
}
```

This creates an IdP-initiated URL at: `http://keycloak-host/realms/realm-name/protocol/saml/clients/saml-proxy`

### Proxy Configuration

No special configuration is required on the proxy side. The proxy automatically detects and handles IdP-initiated flows.

## Usage Examples

### Single SP Configuration

When only one SP is configured, the flow is automatic:

```
User → IdP Login → IdP sends SAML Response → Proxy → Automatic redirect to SP
```

### Multiple SP Configuration

When multiple SPs are configured:

```
User → IdP Login → IdP sends SAML Response → Proxy → SP Selection Page → Selected SP
```

## Testing

### Manual Testing

1. Configure your IdP to support IdP-initiated SSO
2. Log in directly at the IdP
3. Access the IdP-initiated URL or trigger an unsolicited SAML response
4. Verify the proxy correctly handles the response

### Automated Testing

Example test that simulates IdP-initiated flow:

```javascript
// Send SAML response directly to proxy ACS without cookies
const response = await fetch('http://proxy/acs', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'SAMLResponse=' + encodedSAMLResponse
});
```

## Security Considerations

1. **Response Validation**: All SAML responses are validated against the configured IdP certificates
2. **Session Management**: Temporary sessions are created with short expiration times
3. **SP Authorization**: Only configured SPs are available for selection

## Limitations

1. The current implementation requires the SAML response to be properly signed by a configured IdP
2. RelayState is not preserved in IdP-initiated flows (as per SAML specification)
3. The SP selection page is basic HTML - customize as needed for production use

## Troubleshooting

### Common Issues

1. **"Authentication failed" error**: 
   - Verify the IdP certificate is correctly configured
   - Check that the SAML response is properly signed
   - Ensure the IdP entity ID matches the configuration

2. **No SP selection page shown**:
   - Verify multiple SPs are configured
   - Check proxy logs for errors

3. **IdP-initiated URL returns 400**:
   - Ensure the IdP client has the correct attributes configured
   - Verify the user is authenticated at the IdP first

### Debug Logging

Enable debug logging to see detailed information about IdP-initiated flow processing:

```
Detected IdP-initiated flow
Trying to parse response with provider: keycloak-idp
Successfully parsed response
IdP-initiated assertion received
```

## Future Enhancements

1. Support for RelayState preservation where possible
2. Customizable SP selection UI
3. Direct SAML response generation without callback mechanism
4. Support for encrypted assertions in IdP-initiated flow