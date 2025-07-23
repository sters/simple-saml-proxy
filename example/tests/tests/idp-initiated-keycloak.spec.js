const { test, expect } = require('@playwright/test');

test.describe('Keycloak IDP-Initiated Flow with Direct POST', () => {

  test('SP-initiated flow to capture SAML response, then replay as IdP-initiated', async ({ page }) => {
    test.setTimeout(90000);
    console.log('=== Testing IdP-Initiated Flow by Capturing Real SAML Response ===\n');
    
    // Step 1: First do a normal SP-initiated flow to capture a real SAML response
    console.log('Step 1: Performing SP-initiated flow to capture SAML response');
    
    // Start from Keycloak SP
    await page.goto('http://localhost:8081/realms/sp-realm/account/#/');
    await page.waitForTimeout(2000);
    
    // Look for the SAML login option
    const samlLogin = page.locator('a:has-text("saml-proxy"), button:has-text("saml-proxy"), a[href*="saml-proxy"]').first();
    const loginFound = await samlLogin.count() > 0;
    
    if (loginFound) {
      console.log('  Found SAML proxy login option, clicking...');
      
      // Set up request interception to capture SAML responses
      let capturedSAMLResponse = null;
      
      page.on('request', request => {
        const postData = request.postData();
        if (postData && postData.includes('SAMLResponse=')) {
          console.log('  📦 Captured SAML response in POST request');
          // Extract SAMLResponse value
          const match = postData.match(/SAMLResponse=([^&]+)/);
          if (match) {
            capturedSAMLResponse = decodeURIComponent(match[1]);
          }
        }
      });
      
      await samlLogin.click();
      await page.waitForTimeout(2000);
      
      // Select IDP if needed
      const idpButton = page.locator('button:has-text("Development IdP"), input[value="keycloak-idp"]').first();
      if (await idpButton.count() > 0) {
        console.log('  Selecting Development IdP...');
        await idpButton.click();
        await page.waitForTimeout(2000);
      }
      
      // Login at Keycloak IdP
      const usernameField = page.locator('input[name="username"]');
      if (await usernameField.count() > 0) {
        console.log('  Logging in as testuser...');
        await page.fill('input[name="username"]', 'testuser');
        await page.fill('input[name="password"]', 'testpassword');
        await page.click('input[type="submit"]');
        await page.waitForTimeout(5000);
      }
      
      if (capturedSAMLResponse) {
        console.log('\n✓ Successfully captured SAML response');
        console.log(`  Response length: ${capturedSAMLResponse.length} characters`);
        
        // Step 2: Now simulate IdP-initiated flow by sending this response directly to proxy ACS
        console.log('\nStep 2: Simulating IdP-initiated flow with captured SAML response');
        
        // Clear all cookies to simulate a fresh IdP-initiated flow
        await page.context().clearCookies();
        console.log('  Cleared all cookies');
        
        // Create a form that POSTs the SAML response directly to proxy ACS
        await page.setContent(`
          <html>
            <body>
              <h1>Simulating IDP-Initiated SAML Flow</h1>
              <p>Sending SAML response directly to proxy ACS endpoint...</p>
              <form id="samlForm" method="post" action="http://localhost:8082/acs">
                <input type="hidden" name="SAMLResponse" value="${capturedSAMLResponse}" />
              </form>
              <script>
                setTimeout(() => {
                  console.log('Submitting SAML form...');
                  document.getElementById('samlForm').submit();
                }, 1000);
              </script>
            </body>
          </html>
        `);
        
        // Wait for the form submission and navigation
        await page.waitForTimeout(5000);
        
        const currentUrl = page.url();
        console.log(`\n  Current URL after IdP-initiated submission: ${currentUrl}`);
        
        // Check the result
        if (currentUrl.includes('/sp_select')) {
          console.log('✅ SP selection page reached - IdP-initiated flow is working!');
          
          // Look for SP options
          const spButtons = await page.locator('button[type="submit"]').all();
          console.log(`  Found ${spButtons.length} SP option(s)`);
          
          if (spButtons.length > 0) {
            // Get button text
            const buttonText = await spButtons[0].textContent();
            console.log(`  First SP option: ${buttonText}`);
            
            // Click to select SP
            console.log('  Selecting first SP...');
            await spButtons[0].click();
            await page.waitForTimeout(3000);
            
            const finalUrl = page.url();
            console.log(`  Final URL: ${finalUrl}`);
            
            if (finalUrl.includes('localhost:8081')) {
              console.log('\n✅ FULL IDP-INITIATED FLOW SUCCESSFUL!');
              console.log('   - SAML response accepted without cookies');
              console.log('   - SP selection page displayed');
              console.log('   - Successfully redirected to selected SP');
            }
          }
        } else if (currentUrl.includes('error')) {
          console.log('❌ Error in IdP-initiated flow');
          const errorText = await page.textContent('body');
          console.log('  Error:', errorText.substring(0, 200));
        } else {
          console.log('⚠️ Unexpected result');
          const pageContent = await page.textContent('body');
          console.log('  Page content:', pageContent.substring(0, 200));
        }
        
        // Take screenshot for debugging
        await page.screenshot({ path: 'test-results/idp-initiated-keycloak.png', fullPage: true });
        console.log('\n  Screenshot saved to test-results/idp-initiated-keycloak.png');
        
      } else {
        console.log('❌ Failed to capture SAML response');
      }
    } else {
      console.log('❌ SAML proxy login option not found');
    }
  });
});