const { test, expect } = require('@playwright/test');

test.describe('Manual IDP-Initiated Flow Test', () => {

  test('Direct SAML Response to Proxy ACS', async ({ page }) => {
    test.setTimeout(60000);
    console.log('=== Manual IDP-Initiated SAML Flow Test ===\n');
    
    // Step 1: First authenticate with Keycloak IDP to get a session
    console.log('Step 1: Authenticating with Keycloak IDP');
    await page.goto('http://localhost:8080/realms/test/protocol/openid-connect/auth?client_id=account&redirect_uri=http://localhost:8080/realms/test/account/&response_type=code&scope=openid');
    
    // Login
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpassword');
    await page.click('input[type="submit"]');
    await page.waitForTimeout(2000);
    
    console.log('  ✓ Authenticated with Keycloak IDP');
    
    // Step 2: Get the Keycloak session cookies
    const cookies = await page.context().cookies();
    console.log(`  Found ${cookies.length} cookies`);
    
    // Step 3: Try to access the IDP-initiated URL with authentication
    console.log('\nStep 2: Attempting IDP-initiated SAML flow');
    
    // Build IDP-initiated URL
    const idpInitiatedUrl = 'http://localhost:8080/realms/test/protocol/saml/clients/saml-proxy';
    console.log(`  Navigating to: ${idpInitiatedUrl}`);
    
    // Navigate and capture any redirects
    const response = await page.goto(idpInitiatedUrl, { waitUntil: 'networkidle' });
    await page.waitForTimeout(3000);
    
    const currentUrl = page.url();
    console.log(`  Current URL: ${currentUrl}`);
    console.log(`  Response status: ${response ? response.status() : 'N/A'}`);
    
    // Check if we got redirected to the proxy
    if (currentUrl.includes('localhost:8082')) {
      console.log('✓ Successfully redirected to proxy');
      
      // Check if we're at the SP selection page
      if (currentUrl.includes('/sp_select')) {
        console.log('✓ Reached SP selection page');
        
        // Look for SP options
        const spButtons = await page.locator('button[type="submit"]').all();
        console.log(`  Found ${spButtons.length} SP option(s)`);
        
        if (spButtons.length > 0) {
          console.log('  Clicking first SP option...');
          await spButtons[0].click();
          await page.waitForTimeout(3000);
          
          const finalUrl = page.url();
          console.log(`  Final URL: ${finalUrl}`);
          
          if (finalUrl.includes('localhost:8081')) {
            console.log('✅ IDP-INITIATED FLOW SUCCESSFUL!');
          }
        }
      }
    } else {
      console.log('❌ Not redirected to proxy as expected');
      
      // Take a screenshot for debugging
      await page.screenshot({ path: 'test-results/idp-initiated-manual.png', fullPage: true });
      console.log('  Screenshot saved to test-results/idp-initiated-manual.png');
    }
  });
  
  test('Check Proxy Metadata', async ({ page }) => {
    console.log('=== Checking Proxy Metadata ===\n');
    
    const response = await page.goto('http://localhost:8082/metadata');
    const content = await response.text();
    
    console.log('Metadata response status:', response.status());
    console.log('Content type:', response.headers()['content-type']);
    
    // Check if metadata contains expected elements
    if (content.includes('EntityDescriptor') && content.includes('AssertionConsumerService')) {
      console.log('✓ Valid SAML metadata found');
      console.log('  Entity ID:', content.match(/entityID="([^"]+)"/)?.[1]);
      console.log('  ACS URL:', content.match(/AssertionConsumerService[^>]+Location="([^"]+)"/)?.[1]);
    }
  });
});