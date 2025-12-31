.PHONY: help test test-unit test-integration test-all \
        docker-up docker-down docker-logs docker-status \
        ldap-up ldap-down ldap-test ldap-logs \
        postgres-up postgres-down postgres-test postgres-logs \
        clean build release

# Default target
help:
	@echo "USG RADIUS - Available targets:"
	@echo ""
	@echo "  Building:"
	@echo "    build         - Build the project in debug mode"
	@echo "    release       - Build the project in release mode"
	@echo ""
	@echo "  Testing:"
	@echo "    test          - Run all unit tests"
	@echo "    test-unit     - Run unit tests only (no Docker required)"
	@echo "    test-integration - Run integration tests (requires Docker)"
	@echo "    test-all      - Run all tests (unit + integration)"
	@echo ""
	@echo "  Docker Services:"
	@echo "    docker-up     - Start all test services (LDAP + PostgreSQL)"
	@echo "    docker-down   - Stop all test services"
	@echo "    docker-status - Show status of test services"
	@echo "    docker-logs   - Show logs from all test services"
	@echo ""
	@echo "  LDAP Testing:"
	@echo "    ldap-up       - Start LDAP test service"
	@echo "    ldap-down     - Stop LDAP test service"
	@echo "    ldap-test     - Run LDAP integration tests"
	@echo "    ldap-logs     - Show LDAP service logs"
	@echo ""
	@echo "  PostgreSQL Testing:"
	@echo "    postgres-up   - Start PostgreSQL test service"
	@echo "    postgres-down - Stop PostgreSQL test service"
	@echo "    postgres-test - Run PostgreSQL integration tests"
	@echo "    postgres-logs - Show PostgreSQL service logs"
	@echo ""
	@echo "  Cleanup:"
	@echo "    clean         - Clean build artifacts and Docker volumes"
	@echo ""

# Build targets
build:
	cargo build

release:
	cargo build --release

# Test targets
test: test-unit

test-unit:
	cargo test --workspace

test-integration: docker-up
	@echo "Waiting for services to be ready..."
	@sleep 5
	cargo test --test ldap_integration_tests --test postgres_integration_tests -- --ignored --test-threads=1

test-all: test-unit test-integration

# Docker service management
docker-up:
	docker-compose -f docker-compose.test.yml up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@docker-compose -f docker-compose.test.yml ps

docker-down:
	docker-compose -f docker-compose.test.yml down

docker-status:
	docker-compose -f docker-compose.test.yml ps

docker-logs:
	docker-compose -f docker-compose.test.yml logs

# LDAP-specific targets
ldap-up:
	docker-compose -f docker-compose.test.yml up -d openldap
	@echo "Waiting for LDAP to be ready..."
	@sleep 5
	@docker-compose -f docker-compose.test.yml ps openldap

ldap-down:
	docker-compose -f docker-compose.test.yml down openldap

ldap-test: ldap-up
	cargo test --test ldap_integration_tests -- --ignored --test-threads=1

ldap-logs:
	docker-compose -f docker-compose.test.yml logs -f openldap

# PostgreSQL-specific targets
postgres-up:
	docker-compose -f docker-compose.test.yml up -d postgres
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 3
	@docker-compose -f docker-compose.test.yml ps postgres

postgres-down:
	docker-compose -f docker-compose.test.yml down postgres

postgres-test: postgres-up
	cargo test --test postgres_integration_tests -- --ignored --test-threads=1

postgres-logs:
	docker-compose -f docker-compose.test.yml logs -f postgres

# Cleanup
clean:
	cargo clean
	docker-compose -f docker-compose.test.yml down -v
