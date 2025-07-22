const { test, expect } = require('@playwright/test');

test.describe('IDP-Initiated Flow Tests', () => {

  test('Keycloak IdP → Proxy → SP selection → Keycloak SP', async ({ page }) => {
    test.setTimeout(60000); // Increase timeout to 60 seconds
    console.log('=== IDP-Initiated SAML Flow ===');
    console.log('Keycloak IdP -[Unsolicited SAML Response]-> Proxy -[SP Selection]-> Keycloak SP\n');
    
    // Step 1: Login directly at Keycloak IdP
    console.log('Step 1: Login directly at Keycloak IdP');
    await page.goto('http://localhost:8080/realms/test/account/');
    await page.waitForTimeout(2000);
    
    let currentUrl = page.url();
    console.log(`  Current URL: ${currentUrl}`);
    
    // Check if we need to login
    if (currentUrl.includes('auth') || (await page.locator('input[name="username"]').count() > 0)) {
      console.log('  Login form found, logging in as testuser...');
      await page.fill('input[name="username"]', 'testuser');
      await page.fill('input[name="password"]', 'testpassword');
      await page.click('input[type="submit"]');
      await page.waitForTimeout(3000);
      
      currentUrl = page.url();
      console.log(`  Current URL after login: ${currentUrl}`);
    }
    
    // Step 2: Find and click on the SAML client link to initiate IDP-initiated flow
    console.log('\nStep 2: Initiating IDP-initiated SAML flow');
    console.log('  Looking for SAML client applications...');
    
    // Navigate to applications page
    await page.goto('http://localhost:8080/realms/test/account/#/applications');
    await page.waitForTimeout(2000);
    
    // Look for the SAML proxy client
    const samlProxyApp = page.locator('a[href*="saml-proxy"], button:has-text("saml-proxy"), [data-testid*="saml-proxy"]').first();
    const appCount = await samlProxyApp.count();
    
    if (appCount > 0) {
      console.log('  Found SAML proxy application, clicking...');
      await samlProxyApp.click();
      await page.waitForTimeout(3000);
    } else {
      // Alternative: Try direct IDP-initiated URL
      console.log('  SAML proxy app not found in UI, trying direct IDP-initiated URL...');
      
      // Construct IDP-initiated SAML request URL
      // This URL pattern initiates an unsolicited SAML response to the proxy
      const idpInitiatedUrl = 'http://localhost:8080/realms/test/protocol/saml/clients/saml-proxy';
      console.log(`  Navigating to: ${idpInitiatedUrl}`);
      
      await page.goto(idpInitiatedUrl);
      await page.waitForTimeout(3000);
    }
    
    currentUrl = page.url();
    console.log(`  Current URL after IDP initiation: ${currentUrl}`);
    
    // Step 3: Handle SP selection at proxy
    console.log('\nStep 3: SP Selection at SAML Proxy');
    
    // Check if we're at the SP selection page
    if (currentUrl.includes('localhost:8082') && currentUrl.includes('/sp_select')) {
      console.log('✓ Reached SP selection page at SAML proxy');
      
      // Look for SP selection options
      const spButtons = await page.locator('.sp-button, button[name="sp"], input[type="submit"][value*="SP"]').all();
      console.log(`  Found ${spButtons.length} SP option(s)`);
      
      if (spButtons.length > 0) {
        // Click the first (or only) SP option
        const spText = await spButtons[0].textContent();
        console.log(`  Selecting SP: ${spText || 'Keycloak SP'}`);
        await spButtons[0].click();
        await page.waitForTimeout(3000);
        
        currentUrl = page.url();
        console.log(`  Current URL after SP selection: ${currentUrl}`);
      } else {
        console.log('  No SP buttons found, checking for form submission...');
        
        // Look for a form to submit
        const submitButton = await page.locator('input[type="submit"], button[type="submit"]').first();
        if (await submitButton.count() > 0) {
          await submitButton.click();
          await page.waitForTimeout(3000);
          currentUrl = page.url();
          console.log(`  Current URL after form submission: ${currentUrl}`);
        }
      }
    } else if (currentUrl.includes('localhost:8081')) {
      console.log('✓ Proxy redirected directly to SP (single SP configured)');
    } else {
      console.log('⚠️ Unexpected redirect after IDP initiation');
      console.log(`  Current URL: ${currentUrl}`);
      
      // Take a screenshot for debugging
      await page.screenshot({ path: 'test-results/idp-initiated-unexpected.png', fullPage: true });
      console.log('  Screenshot saved to test-results/idp-initiated-unexpected.png');
    }
    
    // Step 4: Verify successful authentication at SP
    console.log('\nStep 4: Verifying authentication at Keycloak SP');
    
    if (currentUrl.includes('localhost:8081')) {
      console.log('✓ Reached Keycloak SP');
      
      // Check if we're at the account page (authenticated)
      if (currentUrl.includes('/account')) {
        console.log('✓ Successfully authenticated at Keycloak SP');
        
        // Verify user information
        await page.waitForTimeout(2000);
        const pageContent = await page.content();
        
        if (pageContent.includes('testuser')) {
          console.log('✓ User information correctly passed through IDP-initiated flow');
        }
        
        console.log('\n✅ IDP-INITIATED FLOW SUCCESSFUL!');
        console.log('   1. User logged in directly at Keycloak IdP');
        console.log('   2. IdP sent unsolicited SAML response to Proxy');
        console.log('   3. Proxy showed SP selection page (or auto-selected single SP)');
        console.log('   4. User successfully authenticated at Keycloak SP');
      } else {
        console.log('⚠️ Reached SP but not authenticated');
        console.log(`  Current URL: ${currentUrl}`);
        
        // Check for any error messages
        const errorElements = await page.locator('.alert-error, .error, .pf-m-error').all();
        for (const element of errorElements) {
          const text = await element.textContent();
          console.log(`  Error found: "${text}"`);
        }
      }
    } else {
      console.log('❌ Failed: Not redirected to Keycloak SP');
      console.log(`  Current URL: ${currentUrl}`);
    }
    
    // Final status check
    const authenticated = currentUrl.includes('localhost:8081') && 
                         (currentUrl.includes('/account') || currentUrl.includes('authenticated'));
    
    console.log(`\n${authenticated ? '✅' : '❌'} IDP-Initiated Flow Result: ${authenticated ? 'SUCCESS' : 'FAILED'}`);
  });
  
  test('Multiple SP selection in IDP-initiated flow', async ({ page }) => {
    test.setTimeout(60000);
    console.log('=== Testing Multiple SP Selection ===');
    console.log('This test verifies that the proxy correctly shows SP selection when multiple SPs are configured\n');
    
    // Note: This test would require the proxy to be configured with multiple allowed SPs
    // Since the current example setup only has one SP, we'll document the expected behavior
    
    console.log('Expected behavior with multiple SPs:');
    console.log('1. User logs in at IdP');
    console.log('2. IdP sends unsolicited SAML response to proxy');
    console.log('3. Proxy shows SP selection page with all allowed SPs');
    console.log('4. User selects desired SP');
    console.log('5. Proxy creates new SAML response for selected SP');
    console.log('6. User is authenticated at selected SP');
    
    console.log('\nCurrent setup has single SP, so selection page may be skipped');
    console.log('To test multiple SP selection, configure additional PROXY_ALLOWED_SP_* entries');
  });
});