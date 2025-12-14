#!/usr/bin/env bash
set -euo pipefail
INFRA_FILE="${TMPDIR:-/tmp}/bspds_test_infra.env"
CONTAINER_PREFIX="bspds-test"
command_exists() {
    command -v "$1" >/dev/null 2>&1
}
if command_exists podman; then
    CONTAINER_CMD="podman"
    if [[ -z "${DOCKER_HOST:-}" ]]; then
        RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
        PODMAN_SOCK="$RUNTIME_DIR/podman/podman.sock"
        if [[ -S "$PODMAN_SOCK" ]]; then
            export DOCKER_HOST="unix://$PODMAN_SOCK"
        fi
    fi
elif command_exists docker; then
    CONTAINER_CMD="docker"
else
    echo "Error: Neither podman nor docker found" >&2
    exit 1
fi
start_infra() {
    echo "Starting test infrastructure..."
    if [[ -f "$INFRA_FILE" ]]; then
        source "$INFRA_FILE"
        if $CONTAINER_CMD ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_PREFIX}-postgres$"; then
            echo "Infrastructure already running (found $INFRA_FILE)"
            cat "$INFRA_FILE"
            return 0
        fi
        echo "Stale infra file found, cleaning up..."
        rm -f "$INFRA_FILE"
    fi
    $CONTAINER_CMD rm -f "${CONTAINER_PREFIX}-postgres" "${CONTAINER_PREFIX}-minio" "${CONTAINER_PREFIX}-valkey" 2>/dev/null || true
    echo "Starting PostgreSQL..."
    $CONTAINER_CMD run -d \
        --name "${CONTAINER_PREFIX}-postgres" \
        -e POSTGRES_PASSWORD=postgres \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_DB=postgres \
        -P \
        --label bspds_test=true \
        postgres:18-alpine >/dev/null
    echo "Starting MinIO..."
    $CONTAINER_CMD run -d \
        --name "${CONTAINER_PREFIX}-minio" \
        -e MINIO_ROOT_USER=minioadmin \
        -e MINIO_ROOT_PASSWORD=minioadmin \
        -P \
        --label bspds_test=true \
        minio/minio:latest server /data >/dev/null
    echo "Starting Valkey..."
    $CONTAINER_CMD run -d \
        --name "${CONTAINER_PREFIX}-valkey" \
        -P \
        --label bspds_test=true \
        valkey/valkey:8-alpine >/dev/null
    echo "Waiting for services to be ready..."
    sleep 2
    PG_PORT=$($CONTAINER_CMD port "${CONTAINER_PREFIX}-postgres" 5432 | head -1 | cut -d: -f2)
    MINIO_PORT=$($CONTAINER_CMD port "${CONTAINER_PREFIX}-minio" 9000 | head -1 | cut -d: -f2)
    VALKEY_PORT=$($CONTAINER_CMD port "${CONTAINER_PREFIX}-valkey" 6379 | head -1 | cut -d: -f2)
    for i in {1..30}; do
        if $CONTAINER_CMD exec "${CONTAINER_PREFIX}-postgres" pg_isready -U postgres >/dev/null 2>&1; then
            break
        fi
        echo "Waiting for PostgreSQL... ($i/30)"
        sleep 1
    done
    for i in {1..30}; do
        if curl -s "http://127.0.0.1:${MINIO_PORT}/minio/health/live" >/dev/null 2>&1; then
            break
        fi
        echo "Waiting for MinIO... ($i/30)"
        sleep 1
    done
    for i in {1..30}; do
        if $CONTAINER_CMD exec "${CONTAINER_PREFIX}-valkey" valkey-cli ping 2>/dev/null | grep -q PONG; then
            break
        fi
        echo "Waiting for Valkey... ($i/30)"
        sleep 1
    done
    echo "Creating MinIO bucket..."
    $CONTAINER_CMD run --rm --network host \
        -e MC_HOST_minio="http://minioadmin:minioadmin@127.0.0.1:${MINIO_PORT}" \
        minio/mc:latest mb minio/test-bucket --ignore-existing >/dev/null 2>&1 || true
    cat > "$INFRA_FILE" << EOF
export DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/postgres"
export TEST_DB_PORT="${PG_PORT}"
export S3_ENDPOINT="http://127.0.0.1:${MINIO_PORT}"
export S3_BUCKET="test-bucket"
export AWS_ACCESS_KEY_ID="minioadmin"
export AWS_SECRET_ACCESS_KEY="minioadmin"
export AWS_REGION="us-east-1"
export VALKEY_URL="redis://127.0.0.1:${VALKEY_PORT}"
export BSPDS_TEST_INFRA_READY="1"
export BSPDS_ALLOW_INSECURE_SECRETS="1"
export SKIP_IMPORT_VERIFICATION="true"
export DISABLE_RATE_LIMITING="1"
EOF
    echo ""
    echo "Infrastructure ready!"
    echo "Config written to: $INFRA_FILE"
    echo ""
    cat "$INFRA_FILE"
}
stop_infra() {
    echo "Stopping test infrastructure..."
    $CONTAINER_CMD rm -f "${CONTAINER_PREFIX}-postgres" "${CONTAINER_PREFIX}-minio" "${CONTAINER_PREFIX}-valkey" 2>/dev/null || true
    rm -f "$INFRA_FILE"
    echo "Infrastructure stopped."
}
status_infra() {
    echo "Test Infrastructure Status:"
    echo "============================"
    if [[ -f "$INFRA_FILE" ]]; then
        echo "Config file: $INFRA_FILE"
        source "$INFRA_FILE"
        echo "Database URL: $DATABASE_URL"
        echo "S3 Endpoint: $S3_ENDPOINT"
    else
        echo "Config file: NOT FOUND"
    fi
    echo ""
    echo "Containers:"
    $CONTAINER_CMD ps -a --filter "label=bspds_test=true" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  (none)"
}
case "${1:-}" in
    start)
        start_infra
        ;;
    stop)
        stop_infra
        ;;
    restart)
        stop_infra
        start_infra
        ;;
    status)
        status_infra
        ;;
    env)
        if [[ -f "$INFRA_FILE" ]]; then
            cat "$INFRA_FILE"
        else
            echo "Infrastructure not running. Run: $0 start" >&2
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|env}"
        echo ""
        echo "Commands:"
        echo "  start   - Start test infrastructure (Postgres, MinIO, Valkey)"
        echo "  stop    - Stop and remove test containers"
        echo "  restart - Stop then start infrastructure"
        echo "  status  - Show infrastructure status"
        echo "  env     - Output environment variables for sourcing"
        exit 1
        ;;
esac
