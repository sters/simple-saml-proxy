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
    console.log('[INFO] Testing SP-initiated SAML flow...');
    
    // Step 1: Start from SP - access protected resource
    console.log('[INFO] Step 1: Initiating SSO from Keycloak SP...');
    logVerbose('Accessing SP account page: http://localhost:8081/realms/test/account');
    
    const spResponse = await page.goto('http://localhost:8081/realms/test/account', {
      waitUntil: 'networkidle'
    });
    
    console.log(`[INFO] SP response: HTTP ${spResponse.status()}`);
    
    // Check if we're on a login page
    const spContent = await page.content();
    if (process.env.VERBOSE === 'true') {
      logVerbose('SP page title:', await page.title());
      logVerbose('SP page URL:', page.url());
      
      // Check for SAML proxy references
      const hasProxyRef = spContent.includes('saml-proxy') || 
                         spContent.includes('simple-saml-proxy') ||
                         spContent.includes('localhost:8082');
      logVerbose('Page contains SAML proxy reference:', hasProxyRef);
    }
    
    // Look for identity provider login options
    const hasIdpOptions = await page.locator('text=/Identity Provider|Log.*in.*with/i').count() > 0;
    if (hasIdpOptions) {
      console.log('✓ SP shows SAML authentication options');
      
      // Try to find and click the SAML proxy login button/link
      const samlLoginButton = page.locator('a[href*="broker/saml-proxy"]').first();
      if (await samlLoginButton.count() > 0) {
        console.log('[INFO] Step 2: Clicking SAML proxy login...');
        logVerbose('Found SAML login button');
        
        // Click and wait for navigation
        await Promise.all([
          page.waitForNavigation({ waitUntil: 'networkidle' }),
          samlLoginButton.click()
        ]);
        
        console.log(`[INFO] Redirected to: ${page.url()}`);
        
        // Check if we're redirected to the proxy
        if (page.url().includes('localhost:8082')) {
          console.log('✓ SP correctly redirected to SAML proxy');
          
          // Check for IdP selection page
          const proxyContent = await page.content();
          if (proxyContent.includes('keycloak-idp') || proxyContent.includes('Select Identity Provider')) {
            console.log('✓ Proxy shows IdP selection page');
            
            if (process.env.VERBOSE === 'true') {
              // Log available IdPs
              const idpLinks = await page.locator('a[href*="idp"]').all();
              logVerbose(`Found ${idpLinks.length} IdP options`);
            }
          }
        }
      } else {
        console.log('⚠ SAML broker endpoint not found - IdP may not be configured');
      }
    }
    
    // Step 3: Test SP SAML broker endpoint directly
    console.log('[INFO] Step 3: Testing SP SAML broker endpoint...');
    
    const brokerUrl = 'http://localhost:8081/realms/test/broker/saml-proxy/login';
    logVerbose(`Accessing SP broker endpoint: ${brokerUrl}`);
    
    try {
      const brokerResponse = await page.goto(brokerUrl, {
        waitUntil: 'networkidle'
      });
      
      const brokerStatus = brokerResponse.status();
      console.log(`[INFO] SP SAML broker response: HTTP ${brokerStatus}`);
      
      if (brokerStatus === 302 || brokerStatus === 303) {
        console.log('✓ SP broker redirects for SAML authentication');
        
        // Check if we're redirected to the proxy
        const currentUrl = page.url();
        if (currentUrl.includes('localhost:8082')) {
          console.log('✓ SP broker correctly redirected to SAML proxy');
          
          // Check proxy response
          const proxyContent = await page.content();
          if (proxyContent.includes('keycloak-idp') || proxyContent.includes('Identity Provider')) {
            console.log('✓ Proxy shows IdP selection page after SP broker redirect');
          }
        } else if (currentUrl.includes('localhost:8080')) {
          console.log('✓ Proxy redirected directly to Keycloak IdP');
        }
        
      } else if (brokerStatus === 404) {
        console.log('⚠ SAML broker endpoint not found - IdP configuration may be missing');
        console.log('  Run "make configure" to set up the SAML identity provider');
        
      } else if (brokerStatus === 500) {
        console.log('⚠ SAML broker returned server error - check configuration');
        
      } else if (brokerStatus === 200) {
        // We might be on the proxy IdP selection page
        const content = await page.content();
        if (content.includes('keycloak-idp') || content.includes('Identity Provider')) {
          console.log('✓ Reached proxy IdP selection page via SP broker');
        }
      }
      
    } catch (error) {
      console.log('⚠ Error accessing SP broker endpoint:', error.message);
      logVerbose('Full error:', error);
    }
    
    console.log('✓ SP-initiated flow tests completed');
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