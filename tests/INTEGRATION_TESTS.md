# Integration Tests

This directory contains integration tests that require real backend services (LDAP, PostgreSQL) running via Docker.

## Quick Start

```bash
# Start all test services
docker-compose -f docker-compose.test.yml up -d

# Wait for services to be ready (check health)
docker-compose -f docker-compose.test.yml ps

# Run all integration tests
cargo test --test ldap_integration_tests --test postgres_integration_tests -- --ignored --test-threads=1

# Stop test services
docker-compose -f docker-compose.test.yml down
```

## Individual Test Suites

### LDAP Integration Tests

```bash
# Start only LDAP service
docker-compose -f docker-compose.test.yml up -d openldap

# Wait for LDAP to be ready
docker-compose -f docker-compose.test.yml exec openldap ldapsearch -x -H ldap://localhost -b dc=example,dc=com -D "cn=admin,dc=example,dc=com" -w admin

# Run LDAP tests
cargo test --test ldap_integration_tests -- --ignored --test-threads=1

# View LDAP server logs
docker-compose -f docker-compose.test.yml logs -f openldap

# Stop LDAP service
docker-compose -f docker-compose.test.yml down openldap
```

### PostgreSQL Integration Tests

```bash
# Start only PostgreSQL service
docker-compose -f docker-compose.test.yml up -d postgres

# Wait for PostgreSQL to be ready
docker-compose -f docker-compose.test.yml exec postgres pg_isready -U radius -d radius_test

# Run PostgreSQL tests
cargo test --test postgres_integration_tests -- --ignored --test-threads=1

# View PostgreSQL logs
docker-compose -f docker-compose.test.yml logs -f postgres

# Connect to PostgreSQL for debugging
docker-compose -f docker-compose.test.yml exec postgres psql -U radius -d radius_test

# Stop PostgreSQL service
docker-compose -f docker-compose.test.yml down postgres
```

## Test Data

### LDAP Test Users

Loaded from `tests/fixtures/ldap/ldif/users.ldif`:

| Username | Password | DN | Groups |
|----------|----------|-----|--------|
| testuser | password123 | uid=testuser,ou=users,dc=example,dc=com | users |
| alice | alice123 | uid=alice,ou=users,dc=example,dc=com | admins |
| bob | bob456 | uid=bob,ou=users,dc=example,dc=com | users |

### PostgreSQL Test Users

Loaded from `tests/fixtures/postgres/test-data.sql`:

| Username | Password | Enabled | Attributes |
|----------|----------|---------|------------|
| testuser | password123 | true | Service-Type=2, Session-Timeout=3600 |
| alice | alice123 | true | Service-Type=2, Session-Timeout=7200, Filter-Id=admin-filter |
| bob | bob456 | true | Service-Type=2, Session-Timeout=1800 |
| disabled | disabled123 | false | None |

## Troubleshooting

### LDAP Connection Issues

```bash
# Check if LDAP is running
docker-compose -f docker-compose.test.yml ps openldap

# Check LDAP logs
docker-compose -f docker-compose.test.yml logs openldap

# Test LDAP connection manually
docker-compose -f docker-compose.test.yml exec openldap ldapsearch -x -H ldap://localhost -b dc=example,dc=com -D "cn=admin,dc=example,dc=com" -w admin

# List users
docker-compose -f docker-compose.test.yml exec openldap ldapsearch -x -H ldap://localhost -b ou=users,dc=example,dc=com -D "cn=admin,dc=example,dc=com" -w admin
```

### PostgreSQL Connection Issues

```bash
# Check if PostgreSQL is running
docker-compose -f docker-compose.test.yml ps postgres

# Check PostgreSQL logs
docker-compose -f docker-compose.test.yml logs postgres

# Test PostgreSQL connection
docker-compose -f docker-compose.test.yml exec postgres psql -U radius -d radius_test -c "SELECT username FROM users;"

# View test data
docker-compose -f docker-compose.test.yml exec postgres psql -U radius -d radius_test -c "SELECT username, enabled FROM users;"
```

### Port Conflicts

If ports 1389, 1636, or 15432 are already in use:

1. Stop the conflicting service
2. Or modify `docker-compose.test.yml` to use different ports
3. Update test connection strings accordingly

### Clean Restart

```bash
# Stop all services and remove volumes
docker-compose -f docker-compose.test.yml down -v

# Start fresh
docker-compose -f docker-compose.test.yml up -d

# Wait for health checks to pass
docker-compose -f docker-compose.test.yml ps
```

## CI/CD Integration

For GitHub Actions or other CI systems:

```yaml
- name: Start test services
  run: docker-compose -f docker-compose.test.yml up -d

- name: Wait for services
  run: |
    docker-compose -f docker-compose.test.yml exec -T openldap timeout 30 sh -c 'until ldapsearch -x -H ldap://localhost -b dc=example,dc=com -D "cn=admin,dc=example,dc=com" -w admin; do sleep 1; done'
    docker-compose -f docker-compose.test.yml exec -T postgres timeout 30 sh -c 'until pg_isready -U radius -d radius_test; do sleep 1; done'

- name: Run integration tests
  run: cargo test --test ldap_integration_tests --test postgres_integration_tests -- --ignored --test-threads=1

- name: Stop test services
  run: docker-compose -f docker-compose.test.yml down
  if: always()
```

## Writing New Integration Tests

1. Add test to appropriate file:
   - `ldap_integration_tests.rs` for LDAP tests
   - `postgres_integration_tests.rs` for PostgreSQL tests

2. Mark test with `#[ignore]` attribute:

   ```rust
   #[tokio::test]
   #[ignore] // Requires Docker
   async fn test_my_feature() {
       // Test code
   }
   ```

3. Add test data if needed:
   - LDAP: Add entries to `tests/fixtures/ldap/ldif/users.ldif`
   - PostgreSQL: Add data to `tests/fixtures/postgres/test-data.sql`

4. Document test in this README

## Test Organization

- **Unit Tests**: Run without external dependencies (`cargo test`)
- **Integration Tests** (this directory): Require Docker services (`cargo test -- --ignored`)
- **End-to-End Tests**: Require full RADIUS client/server setup (future)

## Performance

Integration tests are slower than unit tests due to:

- Docker startup time (5-10 seconds)
- Network latency
- Database/LDAP query time

Use `--test-threads=1` to avoid connection pool exhaustion and race conditions.
