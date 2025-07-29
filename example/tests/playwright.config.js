const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 30000,
  expect: {
    timeout: 5000
  },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.VERBOSE === 'true' ? [['list', { printSteps: true }]] : [['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:10000',
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
  ],

  webServer: {
    command: 'echo "Services should be started via docker-compose"',
    port: 10000,
    reuseExistingServer: !process.env.CI,
  },
});