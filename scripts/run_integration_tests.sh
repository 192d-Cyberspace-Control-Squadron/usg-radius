#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_CMD="${COMPOSE_CMD:-docker-compose}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.test.yml}"
SERVICES=("openldap" "postgres")
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-60}"
KEEP_CONTAINERS="${KEEP_CONTAINERS:-0}"

cleanup() {
    if [[ "$KEEP_CONTAINERS" != "1" ]]; then
        $COMPOSE_CMD -f "$COMPOSE_FILE" down
    fi
}
trap cleanup EXIT

wait_for_health() {
    local service="$1"
    local timeout="$2"

    local container_id
    container_id="$($COMPOSE_CMD -f "$COMPOSE_FILE" ps -q "$service")"
    if [[ -z "$container_id" ]]; then
        echo "error: service '$service' is not running"
        return 1
    fi

    for _ in $(seq 1 "$timeout"); do
        local status
        status="$(docker inspect -f '{{.State.Health.Status}}' "$container_id" 2>/dev/null || true)"
        if [[ "$status" == "healthy" ]]; then
            echo "healthy"
            return 0
        fi
        sleep 1
    done

    echo "unhealthy after ${timeout}s"
    return 1
}

echo "Starting integration test services with $COMPOSE_CMD ($COMPOSE_FILE)..."
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d "${SERVICES[@]}"

echo "Waiting for service health checks..."
for svc in "${SERVICES[@]}"; do
    printf " - %s: " "$svc"
    wait_for_health "$svc" "$HEALTH_TIMEOUT"
done

echo "Running integration tests..."
cargo test --test ldap_integration_tests --test postgres_integration_tests -- --ignored --test-threads=1

echo "Done."
