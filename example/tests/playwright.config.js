const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 30000,
  expect: {
    timeout: 5000
  },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.VERBOSE === 'true' ? [['list', { printSteps: true }]] : 'html',
  use: {
    baseURL: 'http://localhost:8082',
    trace: process.env.VERBOSE === 'true' ? 'on' : 'on-first-retry',
    screenshot: process.env.VERBOSE === 'true' ? 'on' : 'only-on-failure',
    video: process.env.VERBOSE === 'true' ? 'on' : 'retain-on-failure',
    // Add request/response logging in verbose mode
    launchOptions: {
      logger: process.env.VERBOSE === 'true' ? {
        isEnabled: () => true,
        log: (name, severity, message) => console.log(`[${severity}] ${name}: ${message}`)
      } : undefined
    }
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],

  webServer: {
    command: 'echo "Services should be started via docker-compose"',
    port: 8082,
    reuseExistingServer: !process.env.CI,
  },
});