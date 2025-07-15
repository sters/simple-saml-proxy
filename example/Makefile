# Integration Testing Makefile for Simple SAML Proxy

.PHONY: help setup start stop clean test test-basic test-e2e logs status

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Generate certificates and prepare environment
	@echo "Setting up integration testing environment..."
	@./certs/generate-certs.sh
	@echo "Setup complete!"

start: ## Start all services (Keycloak IdP, SP, and SAML Proxy)
	@echo "Starting integration testing environment..."
	@docker-compose up -d
	@echo "Services starting... Use 'make logs' to see output"

configure: ## Configure Keycloak SP with SAML Identity Provider
	@echo "Configuring Keycloak SP..."
	@./scripts/configure-keycloak.sh

stop: ## Stop all services
	@echo "Stopping integration testing environment..."
	@docker-compose down

clean: ## Stop services and remove volumes
	@echo "Cleaning up integration testing environment..."
	@docker-compose down -v --remove-orphans
	@docker system prune -f

test: setup start configure test-e2e ## Run full integration test suite

test-e2e-setup: ## Install Playwright dependencies
	@echo "Setting up Playwright tests..."
	@cd tests && npm install && npx playwright install

test-e2e: test-e2e-setup ## Run end-to-end tests with Playwright
	@echo "Running end-to-end tests..."
	@cd tests && npm test

test-e2e-verbose: test-e2e-setup ## Run end-to-end tests with verbose output
	@echo "Running end-to-end tests (verbose mode)..."
	@cd tests && npm run test:verbose

test-e2e-ui: test-e2e-setup ## Run end-to-end tests with Playwright UI
	@echo "Running end-to-end tests with UI..."
	@cd tests && npm run test:ui

logs: ## Show logs from all services
	@docker-compose logs -f

status: ## Show status of all services
	@docker-compose ps

rebuild: ## Rebuild and restart all services
	@echo "Rebuilding services..."
	@docker-compose down
	@docker-compose build --no-cache
	@docker-compose up -d

# Service-specific commands
logs-proxy: ## Show logs from SAML proxy only
	@docker-compose logs -f simple-saml-proxy

logs-idp: ## Show logs from Keycloak IdP only
	@docker-compose logs -f keycloak-idp

logs-sp: ## Show logs from Keycloak SP only
	@docker-compose logs -f keycloak-sp

shell-proxy: ## Get shell access to SAML proxy container
	@docker-compose exec simple-saml-proxy sh

shell-idp: ## Get shell access to Keycloak IdP container
	@docker-compose exec keycloak-idp bash

shell-sp: ## Get shell access to Keycloak SP container
	@docker-compose exec keycloak-sp bash
