const { test, expect } = require('@playwright/test');

test.describe('Simulated IDP-Initiated Flow', () => {

  test('Simulate unsolicited SAML Response', async ({ page, request }) => {
    test.setTimeout(60000);
    console.log('=== Simulating IDP-Initiated SAML Flow ===\n');
    
    // First, let's check if the proxy is healthy
    const healthCheck = await request.get('http://localhost:8082/ping');
    console.log('Proxy health check:', healthCheck.status());
    
    // Create a mock SAML response (base64 encoded)
    // This is a simplified example - in reality, this would be a properly signed SAML response
    const mockSAMLResponse = Buffer.from(`
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="_${Date.now()}"
                      Version="2.0"
                      IssueInstant="${new Date().toISOString()}"
                      Destination="http://localhost:8082/acs">
        <saml:Issuer>http://localhost:8080/realms/test</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        <saml:Assertion ID="_assertion_${Date.now()}"
                        Version="2.0"
                        IssueInstant="${new Date().toISOString()}">
          <saml:Issuer>http://localhost:8080/realms/test</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">testuser</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="${new Date(Date.now() + 300000).toISOString()}"
                                           Recipient="http://localhost:8082/acs"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="${new Date().toISOString()}"
                          NotOnOrAfter="${new Date(Date.now() + 300000).toISOString()}">
            <saml:AudienceRestriction>
              <saml:Audience>http://localhost:8082</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="${new Date().toISOString()}">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>
            <saml:Attribute Name="email">
              <saml:AttributeValue>testuser@example.com</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
      </samlp:Response>
    `).toString('base64');
    
    console.log('Step 1: Sending unsolicited SAML Response to proxy ACS');
    console.log('  Target URL: http://localhost:8082/acs');
    
    // Navigate to a page that will POST the SAML response
    await page.setContent(`
      <html>
        <body>
          <h1>Simulating IDP-Initiated SAML Flow</h1>
          <form id="samlForm" method="post" action="http://localhost:8082/acs">
            <input type="hidden" name="SAMLResponse" value="${mockSAMLResponse}" />
          </form>
          <script>
            console.log('Submitting SAML form...');
            document.getElementById('samlForm').submit();
          </script>
        </body>
      </html>
    `);
    
    // Wait for navigation
    await page.waitForTimeout(3000);
    
    const currentUrl = page.url();
    console.log(`\nStep 2: Checking result`);
    console.log(`  Current URL: ${currentUrl}`);
    
    // Check if we got the expected IdP-initiated flow detection
    if (currentUrl.includes('/sp_select')) {
      console.log('✓ SP selection page detected - IdP-initiated flow is working!');
      
      // Check for SP options
      const pageContent = await page.content();
      if (pageContent.includes('Select Service Provider')) {
        console.log('✓ SP selection UI is displayed');
      }
    } else if (currentUrl.includes('error') || currentUrl.includes('400')) {
      console.log('❌ Error detected in IdP-initiated flow');
      const pageContent = await page.textContent('body');
      console.log('  Error:', pageContent.substring(0, 200));
    } else {
      console.log('⚠️ Unexpected result');
    }
    
    // Take a screenshot for debugging
    await page.screenshot({ path: 'test-results/idp-initiated-simulation.png', fullPage: true });
    console.log('\n  Screenshot saved to test-results/idp-initiated-simulation.png');
  });
});