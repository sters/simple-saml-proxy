const { test, expect } = require('@playwright/test');

// Test configuration
const CONFIG = {
  sp: {
    url: 'http://localhost:12000/realms/sp-realm',
    accountUrl: 'http://localhost:12000/realms/sp-realm/account/',
    personalInfoUrl: 'http://localhost:12000/realms/sp-realm/account/#/personal-info'
  },
  proxy: {
    url: 'http://localhost:10000'
  },
  idp1: {
    url: 'http://localhost:11001',
    urlPattern: /localhost:11001/,
    credentials: {
      username: 'testuser',
      password: 'testpassword'
    },
    expectedUserData: {
      username: 'testuser',
      firstName: 'Test',
      lastName: 'User'
    }
  },
  idp2: {
    url: 'http://localhost:11002',
    urlPattern: /localhost:11002/,
    credentials: {
      username: 'enterpriseuser',
      password: 'enterprisepassword'
    },
    expectedUserData: {
      username: 'enterpriseuser',
      firstName: 'Enterprise',
      lastName: 'User'
    }
  }
};

test.describe('SAML Proxy Flow Tests', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeEach(async ({ context }) => {
    // Clear all cookies and storage to ensure clean state
    await context.clearCookies();
  });

  test('Complete SAML flow with IDP1: SP → Proxy → IdP1 → Proxy → SP', async ({ page }) => {
    console.log('=== SAML Proxy Flow Test with IDP1 ===');
    console.log('Testing complete flow: SP → Proxy → IdP1 → Proxy → SP\n');

    // Step 1: Navigate to SP and initiate login
    await initiateLogin(page);

    // Step 2: Select SAML Proxy as identity provider
    await selectSAMLProxy(page);

    // Step 3: Verify redirect to proxy
    await verifyProxyRedirect(page);

    // Step 4: Select IdP1 at proxy
    await selectIdPAtProxy(page, 0, 'Development IdP');

    // Step 5: Verify redirect to IdP
    await verifyIdPRedirect(page, CONFIG.idp1.urlPattern);

    // Step 6: Login at IdP
    await loginAtIdP(page, CONFIG.idp1.credentials);

    // Step 7: Handle first broker login if needed
    await handleFirstBrokerLogin(page, CONFIG.idp1.expectedUserData);

    // Step 8: Verify successful authentication
    await verifyAuthentication(page);

    // Step 9: Verify user data transfer
    await verifyUserDataTransfer(page, CONFIG.idp1.expectedUserData);

    console.log('\n✅ SAML flow with IDP1 completed successfully with user data verification');
  });

  test('Complete SAML flow with IDP2: SP → Proxy → IdP2 → Proxy → SP', async ({ page }) => {
    console.log('=== SAML Proxy Flow Test with IDP2 ===');
    console.log('Testing complete flow: SP → Proxy → IdP2 → Proxy → SP\n');

    // Step 1: Navigate to SP and initiate login
    await initiateLogin(page);

    // Step 2: Select SAML Proxy as identity provider
    await selectSAMLProxy(page);

    // Step 3: Verify redirect to proxy
    await verifyProxyRedirect(page);

    // Step 4: Select IdP2 at proxy
    await selectIdPAtProxy(page, 1, 'Enterprise IdP');

    // Step 5: Verify redirect to IdP
    await verifyIdPRedirect(page, CONFIG.idp2.urlPattern);

    // Step 6: Login at IdP
    await loginAtIdP(page, CONFIG.idp2.credentials);

    // Step 7: Handle first broker login if needed
    await handleFirstBrokerLogin(page, CONFIG.idp2.expectedUserData);

    // Step 8: Verify successful authentication
    await verifyAuthentication(page);

    // Step 9: Verify user data transfer
    await verifyUserDataTransfer(page, CONFIG.idp2.expectedUserData);

    console.log('\n✅ SAML flow with IDP2 completed successfully with user data verification');
  });
});

// Helper functions

async function initiateLogin(page) {
  console.log('1. Starting at SP account console');
  await page.goto(CONFIG.sp.accountUrl, { waitUntil: 'networkidle' });

  const signInButton = page.locator('#landingSignInButton, button:has-text("Sign in")');
  await signInButton.click();
  await page.waitForLoadState('networkidle');
}

async function selectSAMLProxy(page) {
  const samlProxyLink = page.locator('a[href*="saml-proxy"], a:has-text("SAML Proxy")');
  await samlProxyLink.click();
}

async function verifyProxyRedirect(page) {
  await page.waitForURL(new RegExp(CONFIG.proxy.url));
  console.log('2. ✓ Redirected to Proxy');
}

async function selectIdPAtProxy(page, index, idpName) {
  // Check if we're on any IDP selection page
  const currentURL = page.url();
  if (currentURL.includes('idp_select')) {
    console.log(`3. Selecting IdP: ${idpName}`);
    const idpButtons = page.locator('.idp-button');
    
    // Try to select by text first
    const idpButton = idpButtons.filter({ hasText: idpName });
    if (await idpButton.count() > 0) {
      await idpButton.click();
    } else {
      // Fallback: select by index
      await idpButtons.nth(index).click();
    }
    
    await page.waitForLoadState('networkidle');
  } else {
    console.log(`3. Not on IDP selection page, current URL: ${currentURL}`);
  }
}

async function verifyIdPRedirect(page, urlPattern) {
  await expect(page).toHaveURL(urlPattern);
  console.log('4. ✓ Redirected to IdP');
}

async function loginAtIdP(page, credentials) {
  console.log('5. Logging in at IdP');
  await page.fill('input[name="username"]', credentials.username);
  await page.fill('input[name="password"]', credentials.password);
  await page.click('input[type="submit"]');
  await page.waitForLoadState('networkidle');
}

async function handleFirstBrokerLogin(page, userData) {
  if (page.url().includes('first-broker-login')) {
    console.log('6. Handling first broker login');
    await page.fill('input[name="firstName"]', userData.firstName);
    await page.fill('input[name="lastName"]', userData.lastName);
    
    const submitButton = page.locator('input[type="submit"], button[type="submit"]').first();
    await submitButton.click();
    await page.waitForLoadState('networkidle');
  }
}

async function verifyAuthentication(page) {
  console.log('7. Checking authentication status...');
  
  // Check for errors
  const currentUrl = page.url();
  console.log(`   Current URL: ${currentUrl}`);
  
  if (currentUrl.includes('localhost:12000') && (await page.content()).includes('Invalid response')) {
    throw new Error('Authentication failed: Invalid response from identity provider');
  }

  // Wait for successful redirect to SP
  await page.waitForURL(/localhost:12000.*account/, { timeout: 10000 });
  console.log('8. ✓ Returned to SP');

  // Verify authentication
  const authenticated = page.url().includes('/account');
  expect(authenticated).toBeTruthy();
  console.log('9. ✓ Authenticated successfully');
}

async function verifyUserDataTransfer(page, expectedUserData) {
  console.log('10. Checking Personal Info...');
  
  // Navigate to personal info page
  await page.waitForTimeout(1000); // Stabilize
  await page.goto(CONFIG.sp.personalInfoUrl);
  await page.waitForLoadState('networkidle');
  
  // Wait for form to load
  await page.waitForSelector('input[type="text"]');
  await page.waitForTimeout(2000); // Allow data to populate
  
  // Verify user data presence
  const pageContent = await page.content();
  console.log('   Checking page for user data...');
  
  const checks = {
    [`${expectedUserData.username} or ${expectedUserData.firstName} ${expectedUserData.lastName}`]: 
      pageContent.includes(expectedUserData.username) || 
      pageContent.includes(`${expectedUserData.firstName} ${expectedUserData.lastName}`),
    [`First name (${expectedUserData.firstName})`]: pageContent.includes(expectedUserData.firstName),
    [`Last name (${expectedUserData.lastName})`]: pageContent.includes(expectedUserData.lastName)
  };
  
  console.log('   User Information found in page:');
  Object.entries(checks).forEach(([label, found]) => {
    console.log(`   - ${label}: ${found}`);
    expect(found).toBeTruthy();
  });
  
  console.log('11. ✓ User information correctly transferred from IdP');
}