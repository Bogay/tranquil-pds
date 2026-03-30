default:
    @just --list

run:
    cargo run -p tranquil-server
run-release:
    cargo run -p tranquil-server --release
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

test-store:
    SQLX_OFFLINE=true cargo nextest run -p tranquil-store --features tranquil-store/test-harness

test-store-sim-nightly:
    SQLX_OFFLINE=true TRANQUIL_SIM_SEEDS=10000 cargo nextest run -p tranquil-store --features tranquil-store/test-harness --profile sim-nightly

test-unit:
    SQLX_OFFLINE=true cargo test --test dpop_unit --test validation_edge_cases --test scope_edge_cases

test-auth:
    ./scripts/run-tests.sh --test oauth --test oauth_lifecycle --test oauth_scopes --test oauth_security --test jwt_security --test session_management --test change_password --test password_reset

test-admin:
    ./scripts/run-tests.sh --test admin_email --test admin_invite --test admin_moderation --test admin_search --test admin_stats

test-sync:
    ./scripts/run-tests.sh --test sync_repo --test sync_blob --test sync_conformance --test sync_deprecated --test firehose_validation

test-repo:
    ./scripts/run-tests.sh --test repo_batch --test repo_blob --test record_validation --test lifecycle_record

test-identity:
    ./scripts/run-tests.sh --test identity --test did_web --test plc_migration --test plc_operations --test plc_validation

test-account:
    ./scripts/run-tests.sh --test lifecycle_session --test delete_account --test invite --test email_update --test account_notifications

test-security:
    ./scripts/run-tests.sh --test security_fixes --test banned_words --test rate_limit --test moderation

test-import:
    ./scripts/run-tests.sh --test import_verification --test import_with_verification

test-misc:
    ./scripts/run-tests.sh --test actor --test commit_signing --test image_processing --test lifecycle_social --test notifications --test server --test signing_key --test verify_live_commit

test *args:
    @just test-store
    @just test-unit
    ./scripts/run-tests.sh {{args}}

test-embedded *args:
    @just test-unit
    SQLX_OFFLINE=true TRANQUIL_TEST_BACKEND=store TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=1 DISABLE_RATE_LIMITING=1 TRANQUIL_LEXICON_OFFLINE=1 SKIP_IMPORT_VERIFICATION=true cargo nextest run -E 'not binary(store_parity)' {{args}}

test-one name:
    ./scripts/run-tests.sh --test {{name}}

infra-start:
    ./scripts/test-infra.sh start
infra-stop:
    ./scripts/test-infra.sh stop
infra-status:
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
podman-up:
    podman compose up -d
podman-down:
    podman compose down
podman-logs:
    podman compose logs -f
container-build:
    podman build -t tranquil-pds:latest .
    podman build -t tranquil-pds-frontend:latest ./frontend

frontend-dev:
    . ~/.deno/env && cd frontend && deno task dev
frontend-build:
    . ~/.deno/env && cd frontend && deno task build
frontend-check:
    . ~/.deno/env && cd frontend && deno task check
frontend-clean:
    rm -rf frontend/dist frontend/node_modules

frontend-test *args:
    . ~/.deno/env && cd frontend && VITEST=true deno task test:run {{args}}
frontend-test-watch:
    . ~/.deno/env && cd frontend && VITEST=true deno task test:watch
frontend-test-ui:
    . ~/.deno/env && cd frontend && VITEST=true deno task test:ui
frontend-test-coverage:
    . ~/.deno/env && cd frontend && VITEST=true deno task test:run --coverage

build-all: frontend-build build
