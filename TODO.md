# TODO: Codebase Cleanup and Refactoring for Publication

## Branch Setup
- [ ] Create a new branch for cleanup work

## Code Cleanup
### Remove unnecessary comments
- [ ] Remove obvious comments that explain what the code does
- [ ] Remove version history/changelog comments
- [ ] Keep only essential documentation comments

### Remove/refactor redundant code
- [ ] Identify and remove unused code
- [ ] Refactor redundant/verbose code sections
- [ ] Clean up any debugging or temporary code

## Directory Structure Cleanup
### e2e directory
- [ ] Remove the e2e directory (appears to be misplaced)

### example directory
- [ ] Ensure example directory is for example usage only, not integration tests
- [ ] Clean up any test-specific code from example directory

### Test file reorganization
- [ ] Move test files from cmd/simple-saml-proxy to appropriate locations
  - [ ] These are handler tests, not true e2e tests
  - [ ] Check for overlap with existing handler tests
  - [ ] Remove duplicate tests

## Example Directory Enhancements
### Add IDP-initiated flow
- [ ] Implement IDP-initiated flow test in example/tests
- [ ] Update example/README.md to document IDP-initiated flow
- [ ] Test flow: Keycloak IDP 1 -> proxy -> SP
  - Note: Since multiple SPs cannot be registered, any IDP will route to the single SP

## Quality Assurance
- [ ] Run `make lint-fix` after each major change
- [ ] Run `make test` to ensure nothing is broken
- [ ] Commit changes incrementally with clear messages
- [ ] Push changes regularly

## Documentation Updates
- [ ] Update example/README.md with IDP-initiated flow documentation
- [ ] Ensure all documentation is accurate and up-to-date

## Final Cleanup
- [ ] Review all files for any remaining cleanup items
- [ ] Ensure consistent code style throughout
- [ ] Remove this TODO.md file before final merge