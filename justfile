default:
    @just --list
run:
    cargo run
run-release:
    cargo run --release
build:
    cargo build
build-release:
    cargo build --release
check:
    cargo check
clippy:
    cargo clippy -- -D warnings
fmt:
    cargo fmt
fmt-check:
    cargo fmt -- --check
lint: fmt-check clippy
# Run tests (auto-starts and auto-cleans containers)
test *args:
    ./scripts/run-tests.sh {{args}}
# Run a specific test file
test-file file:
    ./scripts/run-tests.sh --test {{file}}
# Run tests with testcontainers (slower, no shared infra)
test-standalone:
    BSPDS_ALLOW_INSECURE_SECRETS=1 cargo test
# Manually manage test infrastructure (for debugging)
test-infra-start:
    ./scripts/test-infra.sh start
test-infra-stop:
    ./scripts/test-infra.sh stop
test-infra-status:
    ./scripts/test-infra.sh status
clean:
    cargo clean
doc:
    cargo doc --open
db-create:
    DATABASE_URL="postgres://postgres:postgres@localhost:5432/pds" sqlx database create
db-migrate:
    DATABASE_URL="postgres://postgres:postgres@localhost:5432/pds" sqlx migrate run
db-reset:
    DATABASE_URL="postgres://postgres:postgres@localhost:5432/pds" sqlx database drop -y
    DATABASE_URL="postgres://postgres:postgres@localhost:5432/pds" sqlx database create
    DATABASE_URL="postgres://postgres:postgres@localhost:5432/pds" sqlx migrate run
docker-up:
    docker compose up -d
docker-down:
    docker compose down
docker-logs:
    docker compose logs -f
docker-build:
    docker compose build
# Frontend commands (Deno)
frontend-dev:
    . ~/.deno/env && cd frontend && deno task dev
frontend-build:
    . ~/.deno/env && cd frontend && deno task build
frontend-clean:
    rm -rf frontend/dist frontend/node_modules
# Frontend tests
frontend-test *args:
    . ~/.deno/env && cd frontend && VITEST=true deno task test:run {{args}}
frontend-test-watch:
    . ~/.deno/env && cd frontend && VITEST=true deno task test:watch
frontend-test-ui:
    . ~/.deno/env && cd frontend && VITEST=true deno task test:ui
frontend-test-coverage:
    . ~/.deno/env && cd frontend && VITEST=true deno task test:run --coverage
# Build all (frontend + backend)
build-all: frontend-build build
# Test all (backend + frontend)
test-all: test frontend-test
