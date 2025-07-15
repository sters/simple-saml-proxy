#!/bin/bash

# Setup script for Playwright tests

echo "Setting up Playwright tests..."

# Install npm dependencies
echo "Installing npm packages..."
npm install

# Install Playwright browsers
echo "Installing Playwright browsers..."
npx playwright install

# Install additional dependencies if needed
echo "Installing system dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    # For Debian/Ubuntu systems in CI
    npx playwright install-deps
elif command -v brew >/dev/null 2>&1; then
    # For macOS
    echo "macOS detected - no additional dependencies needed"
fi

echo "Setup complete! You can now run the tests with:"
echo "  npm run test                # Run all tests"
echo "  npm run test:verbose        # Run with verbose output"
echo "  npm run test:saml:verbose   # Run SAML tests with debug info"