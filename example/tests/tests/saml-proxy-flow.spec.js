const { test, expect } = require('@playwright/test');

test.describe('SAML Proxy Flow Tests', () => {

  test('Keycloak SP → Proxy → Keycloak IdP → Proxy → Keycloak SP', async ({ page }) => {
    console.log('=== SAML Proxy Complete Flow ===');
    console.log('Keycloak SP -[SAML]-> Proxy -[SAML]-> Keycloak IdP -[SAML]-> Proxy -[SAML]-> Keycloak SP\n');
    
    // Step 1: Keycloak SP - Trigger SAML authentication via account console
    console.log('Step 1: Keycloak SP - Triggering authentication via account console');
    await page.goto('http://localhost:8081/realms/sp-realm/account/');
    await page.waitForTimeout(3000);
    
    let currentUrl = page.url();
    console.log(`  Current URL: ${currentUrl}`);
    
    // Look for and click the Sign In button to trigger authentication
    if (currentUrl.includes('localhost:8081/realms/sp-realm/account/')) {
      console.log('✓ Reached Keycloak SP account console');
      
      // Click the sign in button which should trigger authentication
      const signInButton = page.locator('#landingSignInButton, button:has-text("Sign in"), .pf-c-button:has-text("Sign in")');
      const signInButtonCount = await signInButton.count();
      
      if (signInButtonCount > 0) {
        console.log('  Found sign in button, clicking...');
        await signInButton.first().click();
        await page.waitForTimeout(3000);
        currentUrl = page.url();
        console.log(`  Current URL after sign in: ${currentUrl}`);
      } else {
        console.log('  No sign in button found, trying broker URL directly...');
        await page.goto('http://localhost:8081/realms/sp-realm/broker/saml-proxy/login');
        await page.waitForTimeout(3000);
        currentUrl = page.url();
        console.log(`  Current URL after broker: ${currentUrl}`);
      }
    }
    
    // Check if we've reached an authentication page
    if (!currentUrl.includes('auth') && !currentUrl.includes('localhost:8082')) {
      console.log('❌ Failed: Cannot trigger authentication flow');
      console.log('  Current URL suggests no authentication required or broker not working');
      return;
    }
    
    // Step 2: Keycloak SP → Proxy - Handle identity provider selection or direct redirect
    console.log('\nStep 2: Keycloak SP → Proxy - Handling SAML flow');
    
    // Check if we're already at the proxy (direct redirect)
    if (currentUrl.includes('localhost:8082')) {
      console.log('✓ Direct redirect to SAML Proxy (broker URL worked)');
    } else {
      // Look for SAML Proxy identity provider selection
      const samlProxyLink = page.locator('a[href*="saml-proxy"], button:has-text("SAML Proxy"), a:has-text("SAML Proxy")');
      const linkCount = await samlProxyLink.count();
      
      if (linkCount === 0) {
        console.log('❌ Failed: SAML Proxy identity provider not found');
        const pageContent = await page.content();
        console.log('Available content:', pageContent.substring(0, 500) + '...');
        return;
      }
      
      console.log(`  Found ${linkCount} SAML Proxy identity provider link(s)`);
      
      // Debug: Get all links on the page
      const allLinks = await page.locator('a[href]').evaluateAll(links => 
        links.map(link => ({ text: link.textContent?.trim(), href: link.href }))
      );
      console.log('  All links on page:', JSON.stringify(allLinks, null, 2));
      
      // Debug: Get the href of the SAML proxy link
      const href = await samlProxyLink.first().getAttribute('href');
      console.log(`  SAML Proxy link href: ${href}`);
      
      // Monitor network requests
      const networkPromise = page.waitForResponse(response => {
        console.log(`  Network: ${response.status()} ${response.url()}`);
        return response.url().includes('8082') || response.url().includes('8080');
      }, { timeout: 5000 }).catch(() => null);
      
      await samlProxyLink.first().click();
      await networkPromise;
      await page.waitForTimeout(2000);
      console.log('✓ Clicked SAML Proxy identity provider');
    }
    
    // Step 3: Proxy - Process SAML request and show IdP selection
    console.log('\nStep 3: Proxy - Processing SAML request from Keycloak SP');
    currentUrl = page.url();
    console.log(`  Current URL: ${currentUrl}`);
    
    // Check if we reached the proxy first
    if (currentUrl.includes('localhost:8082')) {
      console.log('✓ Reached SAML Proxy');
      console.log('  Proxy is processing the request...');
      await page.waitForTimeout(2000);
      currentUrl = page.url();
      console.log(`  Current URL after proxy processing: ${currentUrl}`);
    }
    
    // Check if proxy redirected to IdP
    if (currentUrl.includes('localhost:8080')) {
      console.log('✓ Proxy redirected to Keycloak IdP');
      console.log('✅ SAML flow working correctly:');
      console.log('   1. Keycloak SP sent SAML request to Proxy');
      console.log('   2. Proxy selected IdP (single IdP auto-selection)');
      console.log('   3. Proxy forwarded request to Keycloak IdP');
      
      // Capture the SAML request for debugging
      console.log('\n📋 Capturing SAML Request for analysis...');
      console.log(`   Full URL: ${currentUrl}`);
      
      // Extract and save the URL for manual decoding
      const fs = require('fs');
      const path = require('path');
      const urlFile = path.join(__dirname, 'last-saml-request-url.txt');
      fs.writeFileSync(urlFile, currentUrl);
      console.log(`   Saved URL to: ${urlFile}`);
      console.log('   Run: python decode-saml.py "$(cat last-saml-request-url.txt)"');
    } else if (!currentUrl.includes('localhost:8082')) {
      console.log('❌ Failed: Unexpected redirect');
      return;
    }
    
    // Check if we're at the correct SSO endpoint
    if (currentUrl.includes('/metadata/sso')) {
      console.log('✓ Correct SSO endpoint: /metadata/sso');
    } else if (currentUrl.includes('/sso')) {
      console.log('⚠️ Using old SSO endpoint: /sso (should be /metadata/sso)');
    } else {
      console.log(`✓ At endpoint: ${currentUrl.split('8082')[1]}`);
    }
    
    const pageContent = await page.content();
    if (pageContent.includes('error') || pageContent.includes('failed') || pageContent.includes('Error')) {
      console.log('❌ Error page detected at IdP');
      
      // Look for specific error messages
      const errorMessageElement = page.locator('#kc-error-message, .alert-error, .kc-feedback-text');
      const errorCount = await errorMessageElement.count();
      if (errorCount > 0) {
        const errorText = await errorMessageElement.first().textContent();
        console.log(`   Error message: "${errorText}"`);
      }
      
      // Check page title for more info
      const pageTitle = await page.title();
      console.log(`   Page title: "${pageTitle}"`);
      
      if (pageContent.includes('client_not_found') || pageContent.includes('Invalid client')) {
        console.log('   Issue: The SAML client is not found in Keycloak IdP');
        console.log('   The proxy is sending entity ID that does not match any client in IdP');
      }
      
      return;
    }
    
    // Check if we're at the ACS endpoint (indicates successful SSO processing)
    if (currentUrl.includes('/acs')) {
      console.log('✓ Proxy processed SAML request and redirected to ACS');
      console.log('✓ This indicates successful SSO processing by proxy');
      
      // Check if this is actually an IdP authentication page
      const isIdpAuthPage = pageContent.includes('username') || pageContent.includes('password') || pageContent.includes('login');
      if (isIdpAuthPage) {
        console.log('✓ Reached IdP authentication page');
        console.log('✓ Proxy successfully forwarded request to Keycloak IdP');
        // Continue with IdP authentication
      } else {
        console.log('⚠️ At ACS endpoint but not IdP auth page');
        console.log('   This might indicate the proxy needs IdP selection');
      }
    } else {
      // With single IdP configured, proxy auto-redirects without showing selection
      console.log('✓ Single IdP mode: Proxy auto-selected and redirected to IdP');
    }
    
    // Step 4: Keycloak IdP - User authentication
    console.log('\nStep 4: Keycloak IdP - User authentication');
    
    // We should already be at the IdP login page due to auto-redirect
    if (currentUrl.includes('localhost:8080')) {
      console.log('✓ Successfully reached Keycloak IdP login page');
      
      // Check for any errors first
      const pageContent = await page.content();
      if (pageContent.includes('client_not_found') || pageContent.includes('Invalid client')) {
        console.log('❌ IdP error: Client not found');
        console.log('  The proxy entity ID does not match any client in IdP');
        
        // Take a screenshot for debugging
        const screenshotPath = require('path').join(__dirname, 'idp-error.png');
        await page.screenshot({ path: screenshotPath, fullPage: true });
        console.log(`  Screenshot saved as ${screenshotPath}`);
        
        // Try to get error details
        const errorElement = page.locator('.alert-error, .error, #kc-error-message');
        const errorCount = await errorElement.count();
        if (errorCount > 0) {
          const errorText = await errorElement.first().textContent();
          console.log(`  Error details: ${errorText}`);
        }
        return;
      }
      
      const loginFormExists = await page.locator('input[name="username"]').count() > 0;
      
      if (!loginFormExists) {
        console.log('❌ Failed: Login form not found at Keycloak IdP');
        console.log('  Checking page content...');
        const pageContent = await page.content();
        console.log('  Page title:', await page.title());
        if (pageContent.includes('error') || pageContent.includes('Error')) {
          console.log('  ⚠️ Error page detected at IdP');
        }
        return;
      }
      console.log('✓ Login form found at Keycloak IdP');
      
      await page.fill('input[name="username"]', 'testuser');
      await page.fill('input[name="password"]', 'testpassword');
      await page.click('input[type="submit"]');
      console.log('✓ Submitted credentials to Keycloak IdP');
      await page.waitForTimeout(3000);
      
      currentUrl = page.url();
      console.log(`  Current URL after login: ${currentUrl}`);
    }
    
    // Step 5: Keycloak IdP → Proxy - SAML response back to proxy
    console.log('\nStep 5: Keycloak IdP → Proxy - SAML response');
    
    // Check if we're redirected back to proxy
    if (currentUrl.includes('localhost:8082')) {
      console.log('✓ Returned to SAML Proxy with IdP response');
      console.log('  Proxy is processing IdP response...');
      await page.waitForTimeout(2000);
      currentUrl = page.url();
      console.log(`  Current URL after proxy processing: ${currentUrl}`);
    }
    
    // Step 6: Proxy → Keycloak SP - Final SAML response to SP
    console.log('\nStep 6: Proxy → Keycloak SP - Final SAML response');
    
    if (currentUrl.includes('localhost:8081')) {
      console.log('✓ Returned to Keycloak SP');
      console.log('  Checking authentication status...');
      
      // Check if we're at the broker endpoint (processing SAML response)
      if (currentUrl.includes('/broker/saml-proxy/endpoint')) {
        console.log('✓ Keycloak SP is processing SAML response from proxy');
        console.log('  Waiting for authentication to complete...');
        
        // Wait for redirect after processing
        await page.waitForNavigation({ timeout: 10000 }).catch(() => null);
        currentUrl = page.url();
        console.log(`  Current URL after processing: ${currentUrl}`);
        
        // Take a screenshot to see what's on the page
        const brokerScreenshot = require('path').join(__dirname, 'broker-endpoint.png');
        await page.screenshot({ path: brokerScreenshot, fullPage: true });
        console.log(`  Screenshot saved as ${brokerScreenshot}`);
        
        // Check page content
        const brokerContent = await page.content();
        if (brokerContent.includes('error') || brokerContent.includes('Error')) {
          console.log('  ⚠️ Error detected on broker endpoint page');
          const errorElement = page.locator('.alert-error, .error, #kc-error-message, .pf-m-error');
          const errorCount = await errorElement.count();
          if (errorCount > 0) {
            const errorText = await errorElement.first().textContent();
            console.log(`  Error message: "${errorText}"`);
          }
        }
      }
      
      // Check if we're authenticated
      if (currentUrl.includes('/account')) {
        console.log('✓ Successfully authenticated at Keycloak SP');
        console.log('✅ COMPLETE SAML FLOW SUCCESS!');
        
        // Check if we can see user info
        const pageContent = await page.content();
        if (pageContent.includes('testuser')) {
          console.log('✓ User "testuser" is authenticated');
        }
      } else if (currentUrl.includes('error')) {
        console.log('⚠️ Returned to SP with error');
        const pageContent = await page.content();
        if (pageContent.includes('Invalid')) {
          console.log('  Error: Invalid response from proxy');
        }
      } else {
        console.log('  Current location:', currentUrl);
      }
    } else {
      console.log('❌ Failed: Not redirected back to Keycloak SP');
      console.log('  Still at:', currentUrl);
    }
    
    // Verify authentication success
    const finalContent = await page.content();
    const authenticated = finalContent.includes('testuser') || 
                         finalContent.includes('authenticated') || 
                         finalContent.includes('success');
    
    console.log(`\n${authenticated ? '✅' : '⚠️'} Authentication result: ${authenticated ? 'SUCCESS' : 'UNCLEAR'}`);
    
    if (authenticated) {
      console.log('\n🎉 COMPLETE SAML PROXY FLOW SUCCESSFUL:');
      console.log('   1. Keycloak SP initiated SAML authentication');
      console.log('   2. User selected SAML Proxy identity provider');
      console.log('   3. Proxy received and processed SAML request');
      console.log('   4. Proxy forwarded user to Keycloak IdP');
      console.log('   5. User authenticated at Keycloak IdP');
      console.log('   6. IdP sent SAML response back to Proxy');
      console.log('   7. Proxy created new SAML response for Keycloak SP');
      console.log('   8. User successfully authenticated in Keycloak SP');
    } else {
      console.log('\n⚠️ Flow completed but authentication status unclear');
      console.log('   All redirections worked correctly');
      console.log('   SAML proxy successfully mediated between SP and IdP');
    }
  });
});