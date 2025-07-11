.PHONY: help up down restart logs certs clean build

# Default target
help:
	@echo "Available targets:"
	@echo "  make certs    - Generate self-signed certificates"
	@echo "  make up       - Start all services with docker compose"
	@echo "  make down     - Stop all services"
	@echo "  make restart  - Restart all services"
	@echo "  make logs     - Show logs from all services"
	@echo "  make clean    - Clean up certificates and containers"
	@echo "  make build    - Build and start services"

# Generate certificates
certs:
	@echo "Generating certificates..."
	@cd docker/certs && ./generate-certs.sh
	@echo "Certificates generated successfully!"

# Start services
up: certs
	@echo "Starting services..."
	docker compose up -d --build --force-recreate --remove-orphans
	@echo ""
	@echo "Services are running:"
	@echo "  - Service Provider: http://localhost:8001/simplesaml/"
	@echo "  - SAML Proxy:       http://localhost:8080/"
	@echo "  - Identity Provider: http://localhost:8000/simplesaml/"
	@echo ""
	@echo "Admin password for SimpleSAMLphp: admin123"
	@echo "Test users: user1/password, user2/password"

# Stop services
down:
	@echo "Stopping services..."
	docker compose down

# Restart services
restart: down up

# Show logs
logs:
	docker compose logs -f

# Build and start
build: certs
	@echo "Building and starting services..."
	docker compose up -d --build

# Clean up
clean:
	@echo "Cleaning up..."
	docker compose down -v
	rm -f docker/certs/*.crt docker/certs/*.key docker/certs/*.pem
	@echo "Cleanup complete!"

# Service-specific targets
.PHONY: logs-proxy logs-idp logs-sp

logs-proxy:
	docker compose logs -f simple-saml-proxy

logs-idp:
	docker compose logs -f test-idp

logs-sp:
	docker compose logs -f test-sp
