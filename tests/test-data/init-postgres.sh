#!/bin/bash
# PostgreSQL Test Data Initialization Script
# This script loads test data into the PostgreSQL test container

set -e

echo "Waiting for PostgreSQL server to be ready..."
timeout=30
while [ $timeout -gt 0 ]; do
    if PGPASSWORD=postgres psql -h localhost -U postgres -d radius -c "SELECT 1" >/dev/null 2>&1; then
        echo "PostgreSQL server is ready!"
        break
    fi
    echo "Waiting... ($timeout seconds remaining)"
    sleep 1
    timeout=$((timeout - 1))
done

if [ $timeout -eq 0 ]; then
    echo "ERROR: PostgreSQL server failed to become ready"
    exit 1
fi

echo "Loading test data into PostgreSQL..."
PGPASSWORD=postgres psql -h localhost -U postgres -d radius -f "$(dirname "$0")/init-postgres.sql"

echo "PostgreSQL test data initialization complete!"
