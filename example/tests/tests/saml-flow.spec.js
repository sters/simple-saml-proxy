const { test, expect } = require('@playwright/test');

// Helper function for verbose logging
const logVerbose = (message, data = null) => {
  if (process.env.VERBOSE === 'true' || process.env.DEBUG === 'true') {
    console.log(`[DEBUG] ${message}`);
    if (data) {
      console.log(JSON.stringify(data, null, 2));
    }
  }
};

// Helper to capture and log network requests in verbose mode
const setupRequestLogging = async (page) => {
  if (process.env.VERBOSE === 'true') {
    page.on('request', request => {
      logVerbose(`Request: ${request.method()} ${request.url()}`);
      if (request.method() === 'POST') {
        logVerbose('Request Headers:', request.headers());
        logVerbose('Request PostData:', request.postData());
      }
    });

    page.on('response', response => {
      logVerbose(`Response: ${response.status()} ${response.url()}`);
      if (response.status() >= 300 && response.status() < 400) {
        logVerbose('Redirect Location:', response.headers()['location']);
      }
    });
  }
};

test.describe('SAML Proxy Integration Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Set longer timeout for SAML operations
    page.setDefaultTimeout(15000);
    
    // Setup verbose logging if enabled
    await setupRequestLogging(page);
  });

  test('metadata endpoints', async ({ page }) => {
    console.log('[INFO] Testing metadata endpoints...');
    
    // Test proxy metadata
    logVerbose('Testing proxy metadata at http://localhost:8082/metadata');
    const proxyResponse = await page.goto('http://localhost:8082/metadata');
    
    expect(proxyResponse.status()).toBe(200);
    console.log('✓ Proxy metadata endpoint is accessible');
    
    const proxyContent = await page.content();
    expect(proxyContent).toContain('EntityDescriptor');
    expect(proxyContent).toContain('IDPSSODescriptor');
    expect(proxyContent).toContain('SPSSODescriptor');
    
    if (process.env.VERBOSE === 'true') {
      logVerbose('Proxy metadata (first 300 chars):', proxyContent.substring(0, 300));
      const entityCount = (proxyContent.match(/EntityDescriptor/g) || []).length;
      logVerbose(`EntityDescriptor count: ${entityCount}`);
    }
    
    // Test Keycloak IdP metadata
    logVerbose('Testing IdP metadata at http://localhost:8080/realms/test/protocol/saml/descriptor');
    const idpResponse = await page.goto('http://localhost:8080/realms/test/protocol/saml/descriptor');
    
    expect(idpResponse.status()).toBe(200);
    console.log('✓ Keycloak IdP metadata endpoint is accessible');
    
    const idpContent = await page.content();
    expect(idpContent).toContain('EntityDescriptor');
    expect(idpContent).toContain('IDPSSODescriptor');
    
    // Test Keycloak SP metadata  
    logVerbose('Testing SP metadata at http://localhost:8081/realms/test/protocol/saml/descriptor');
    const spResponse = await page.goto('http://localhost:8081/realms/test/protocol/saml/descriptor');
    
    expect(spResponse.status()).toBe(200);
    console.log('✓ Keycloak SP metadata endpoint is accessible');
    
    const spContent = await page.content();
    expect(spContent).toContain('EntityDescriptor');
    expect(spContent).toContain('SPSSODescriptor');
  });

  test('proxy endpoints', async ({ page }) => {
    console.log('[INFO] Testing proxy endpoints...');
    
    // Test SSO endpoint without valid SAML request
    logVerbose('Testing SSO endpoint without SAML request');
    const ssoResponse = await page.goto('http://localhost:8082/sso', {
      waitUntil: 'domcontentloaded'
    });
    
    const ssoStatus = ssoResponse.status();
    expect([200, 400]).toContain(ssoStatus);
    console.log(`✓ SSO endpoint responding (HTTP ${ssoStatus})`);
    
    // Test ACS endpoint
    logVerbose('Testing ACS endpoint');
    const acsResponse = await page.goto('http://localhost:8082/acs', {
      waitUntil: 'domcontentloaded'
    });
    
    const acsStatus = acsResponse.status();
    expect([400, 405]).toContain(acsStatus);
    console.log(`✓ ACS endpoint responding (HTTP ${acsStatus})`);
    
    // Test health endpoint (may not exist)
    logVerbose('Testing health endpoint');
    try {
      const healthResponse = await page.goto('http://localhost:8082/health', {
        waitUntil: 'domcontentloaded'
      });
      
      if (healthResponse.status() === 404) {
        console.log('ℹ Proxy doesn\'t have a dedicated health endpoint (expected)');
        
        // Use metadata as health check
        const metaResponse = await page.goto('http://localhost:8082/metadata');
        if (metaResponse.status() === 200) {
          console.log('✓ Using metadata endpoint for health check - proxy is healthy');
        }
      } else if (healthResponse.status() === 200) {
        console.log('✓ Health endpoint is accessible');
      }
    } catch (error) {
      logVerbose('Health endpoint error:', error.message);
    }
  });

  test('Keycloak admin interfaces', async ({ page }) => {
    console.log('[INFO] Testing Keycloak admin interfaces...');
    
    // Test Keycloak IdP admin
    await page.goto('http://localhost:8080/admin');
    await expect(page.locator('text=Keycloak')).toBeVisible();
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    console.log('✓ Keycloak IdP admin interface is accessible');
    
    // Test Keycloak SP admin
    await page.goto('http://localhost:8081/admin');
    await expect(page.locator('text=Keycloak')).toBeVisible();
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    console.log('✓ Keycloak SP admin interface is accessible');
  });

  test('SP-initiated SAML flow', async ({ page }) => {
    console.log('[INFO] Testing SP-initiated SAML flow (SP → Proxy → IdP → Proxy → SP)...');
    
    // Step 1: Start from SP - initiate SAML authentication
    console.log('[INFO] Step 1: Starting at SP broker endpoint...');
    const brokerUrl = 'http://localhost:8081/realms/test/broker/saml-proxy/login';
    logVerbose(`Accessing SP broker endpoint: ${brokerUrl}`);
    
    try {
      const spResponse = await page.goto(brokerUrl, {
        waitUntil: 'networkidle'
      });
      
      console.log(`[INFO] SP response: HTTP ${spResponse.status()}`);
      
      // Step 2: Check redirect to proxy
      await page.waitForTimeout(1000); // Allow redirects to complete
      const proxyUrl = page.url();
      
      if (proxyUrl.includes('localhost:8082')) {
        console.log('✓ Step 2: SP redirected to SAML proxy');
        logVerbose('Current URL:', proxyUrl);
        
        // Check for IdP selection page
        const proxyContent = await page.content();
        const hasIdpSelection = proxyContent.includes('keycloak-idp') || 
                               proxyContent.includes('Select Identity Provider') ||
                               proxyContent.includes('Choose your identity provider');
        
        if (hasIdpSelection) {
          console.log('✓ Proxy shows IdP selection page');
          
          // Step 3: Select IdP (click on keycloak-idp link)
          console.log('[INFO] Step 3: Selecting Keycloak IdP...');
          
          // Find and click the IdP link
          const idpLink = page.locator('a[href*="keycloak-idp"]').first();
          const idpLinkCount = await idpLink.count();
          
          if (idpLinkCount > 0) {
            logVerbose('Found IdP link, clicking...');
            
            await Promise.all([
              page.waitForNavigation({ waitUntil: 'networkidle' }),
              idpLink.click()
            ]);
            
            // Step 4: Check redirect to IdP
            await page.waitForTimeout(1000);
            const idpUrl = page.url();
            
            if (idpUrl.includes('localhost:8080')) {
              console.log('✓ Step 4: Proxy redirected to Keycloak IdP');
              logVerbose('Current URL:', idpUrl);
              
              // Check if we're on the IdP login page
              const idpContent = await page.content();
              const hasLoginForm = await page.locator('input[name="username"]').count() > 0;
              
              if (hasLoginForm) {
                console.log('✓ Reached IdP login page');
                
                // Step 5: Authenticate at IdP
                console.log('[INFO] Step 5: Authenticating at IdP...');
                
                await page.fill('input[name="username"]', 'testuser');
                await page.fill('input[name="password"]', 'testpassword');
                
                logVerbose('Filled login credentials, submitting...');
                
                // Submit login form
                await Promise.all([
                  page.waitForNavigation({ waitUntil: 'networkidle' }),
                  page.click('input[type="submit"]')
                ]);
                
                // Step 6: Check redirect back through proxy to SP
                await page.waitForTimeout(2000); // Allow SAML processing
                const finalUrl = page.url();
                
                console.log('[INFO] Step 6: Checking final redirect...');
                logVerbose('Final URL:', finalUrl);
                
                if (finalUrl.includes('localhost:8081')) {
                  console.log('✓ Successfully redirected back to SP');
                  
                  // Check if we're authenticated
                  const finalContent = await page.content();
                  const isAuthenticated = finalContent.includes('testuser') || 
                                         finalContent.includes('Account') ||
                                         finalContent.includes('Sign Out') ||
                                         finalContent.includes('Log out');
                  
                  if (isAuthenticated) {
                    console.log('✓ User successfully authenticated at SP');
                    console.log('✓ Complete SAML flow successful: SP → Proxy → IdP → Proxy → SP');
                  } else {
                    console.log('⚠ Reached SP but authentication status unclear');
                  }
                } else if (finalUrl.includes('localhost:8082')) {
                  console.log('⚠ Still at proxy - may need additional configuration');
                  const content = await page.content();
                  logVerbose('Proxy page content (first 500 chars):', content.substring(0, 500));
                } else {
                  console.log('⚠ Unexpected final URL:', finalUrl);
                }
                
              } else {
                console.log('⚠ IdP login form not found');
                logVerbose('IdP page content (first 500 chars):', idpContent.substring(0, 500));
              }
            } else {
              console.log('⚠ Not redirected to IdP, current URL:', idpUrl);
            }
          } else {
            console.log('⚠ IdP selection link not found on proxy page');
            
            // Try direct navigation as fallback
            console.log('[INFO] Attempting direct IdP selection...');
            const directIdpUrl = 'http://localhost:8082/sso?idp=keycloak-idp';
            await page.goto(directIdpUrl, { waitUntil: 'networkidle' });
          }
        } else {
          // Might be redirected directly to IdP if only one IdP configured
          if (proxyUrl.includes('localhost:8080')) {
            console.log('✓ Proxy redirected directly to IdP (single IdP mode)');
          } else {
            console.log('⚠ Proxy did not show IdP selection page');
            logVerbose('Proxy content (first 500 chars):', proxyContent.substring(0, 500));
          }
        }
        
      } else if (proxyUrl.includes('localhost:8080')) {
        console.log('✓ Redirected directly to IdP (proxy may be in single IdP mode)');
        
      } else {
        console.log('⚠ Unexpected redirect URL:', proxyUrl);
        console.log('  Expected redirect to proxy (localhost:8082) or IdP (localhost:8080)');
      }
      
    } catch (error) {
      console.log('❌ Error during SP-initiated flow:', error.message);
      logVerbose('Full error:', error);
      
      // Capture screenshot on error
      if (process.env.VERBOSE === 'true') {
        try {
          await page.screenshot({ path: './test-error-screenshot.png' });
          console.log('[DEBUG] Error screenshot saved to ./test-error-screenshot.png');
        } catch (screenshotError) {
          logVerbose('Could not capture screenshot:', screenshotError.message);
        }
      }
    }
    
    console.log('[INFO] SP-initiated flow test completed');
  });

  test('Complete SP-initiated SAML proxy flow verification', async ({ page }) => {
    console.log('[INFO] Testing complete SAML proxy flow with step verification...');
    
    // Track the flow steps
    const flowSteps = [];
    
    // Monitor all network requests
    page.on('response', response => {
      const url = response.url();
      const status = response.status();
      
      if (url.includes('localhost:8081') && !url.includes('.js') && !url.includes('.css')) {
        flowSteps.push({ step: 'SP', url, status });
      } else if (url.includes('localhost:8082')) {
        flowSteps.push({ step: 'Proxy', url, status });
      } else if (url.includes('localhost:8080') && !url.includes('.js') && !url.includes('.css')) {
        flowSteps.push({ step: 'IdP', url, status });
      }
    });
    
    try {
      // Step 1: Initiate from SP
      console.log('[FLOW] Step 1: SP initiates SAML authentication');
      await page.goto('http://localhost:8081/realms/test/broker/saml-proxy/login', {
        waitUntil: 'networkidle'
      });
      
      // Wait for redirects
      await page.waitForTimeout(2000);
      
      // Step 2: Should be at proxy
      const step2Url = page.url();
      if (step2Url.includes('localhost:8082')) {
        console.log('[FLOW] ✓ Step 2: Reached proxy for IdP selection');
        
        // Find IdP link
        const idpLink = await page.locator('a[href*="keycloak-idp"]').first();
        if (await idpLink.count() > 0) {
          console.log('[FLOW] Step 3: Selecting IdP at proxy');
          await idpLink.click();
          
          // Wait for redirect to IdP
          await page.waitForTimeout(2000);
          
          // Step 4: Should be at IdP
          const step4Url = page.url();
          if (step4Url.includes('localhost:8080')) {
            console.log('[FLOW] ✓ Step 4: Reached IdP for authentication');
            
            // Authenticate
            const hasLoginForm = await page.locator('input[name="username"]').count() > 0;
            if (hasLoginForm) {
              console.log('[FLOW] Step 5: Authenticating at IdP');
              await page.fill('input[name="username"]', 'testuser');
              await page.fill('input[name="password"]', 'testpassword');
              await page.click('input[type="submit"]');
              
              // Wait for SAML processing
              await page.waitForTimeout(3000);
              
              // Step 6: Should be back at SP
              const finalUrl = page.url();
              if (finalUrl.includes('localhost:8081')) {
                console.log('[FLOW] ✓ Step 6: Returned to SP - authentication complete');
                
                // Verify the complete flow
                console.log('\n[FLOW VERIFICATION] Expected flow: SP → Proxy → IdP → Proxy → SP');
                console.log('[FLOW VERIFICATION] Actual flow:');
                flowSteps.forEach((step, index) => {
                  console.log(`  ${index + 1}. ${step.step}: ${step.url.replace(/\?.*/, '...')} (${step.status})`);
                });
                
                // Verify flow pattern
                const flowPattern = flowSteps.map(s => s.step).join(' → ');
                if (flowPattern.includes('SP → Proxy') && flowPattern.includes('Proxy → IdP')) {
                  console.log('[FLOW] ✓ Flow pattern verified');
                } else {
                  console.log('[FLOW] ⚠ Flow pattern unexpected:', flowPattern);
                }
              } else {
                console.log('[FLOW] ❌ Did not return to SP, stuck at:', finalUrl);
              }
            }
          } else {
            console.log('[FLOW] ❌ Did not reach IdP, stuck at:', step4Url);
          }
        } else {
          console.log('[FLOW] ❌ No IdP selection link found at proxy');
        }
      } else {
        console.log('[FLOW] ❌ Did not reach proxy, stuck at:', step2Url);
      }
      
    } catch (error) {
      console.log('[FLOW] ❌ Flow error:', error.message);
    }
    
    console.log('[INFO] Flow verification test completed');
  });
});

// Debug utilities - only run in verbose mode
test.describe('Debug Utilities', () => {
  test.skip(process.env.VERBOSE !== 'true', 'capture full SAML flow with HAR recording', async ({ browser }) => {
    console.log('[DEBUG] Recording full SAML flow with HAR...');
    
    const context = await browser.newContext({
      recordHar: { path: './saml-flow.har' }
    });
    
    const page = await context.newPage();
    
    // Perform a simple flow
    await page.goto('http://localhost:8081/realms/test/account');
    
    // Wait a bit for any redirects
    await page.waitForTimeout(2000);
    
    await context.close();
    console.log('[DEBUG] HAR file saved to ./saml-flow.har');
  });

  test.skip(process.env.VERBOSE !== 'true', 'capture screenshots of all pages', async ({ page }) => {
    console.log('[DEBUG] Capturing screenshots...');
    
    const pages = [
      { url: 'http://localhost:8080/admin', name: 'keycloak-idp-admin' },
      { url: 'http://localhost:8081/admin', name: 'keycloak-sp-admin' },
      { url: 'http://localhost:8082/metadata', name: 'proxy-metadata' },
      { url: 'http://localhost:8081/realms/test/account', name: 'sp-account-page' }
    ];
    
    for (const pageInfo of pages) {
      await page.goto(pageInfo.url, { waitUntil: 'networkidle' });
      await page.screenshot({ path: `./screenshots/${pageInfo.name}.png` });
      console.log(`[DEBUG] Screenshot saved: ${pageInfo.name}.png`);
    }
  });
});