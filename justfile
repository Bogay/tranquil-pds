default:
    @just --list

run:
    cargo run -p tranquil-server
run-dev:
    docker compose --profile dev up
run-release:
    cargo run -p tranquil-server --release
gen-config:
    cargo run -p tranquil-server -- config-template > example.toml
build:
    cargo build
build-release:
    cargo build --release
check:
    cargo check
clippy:
    cargo clippy --all-targets -- -D warnings
lint-no-bsky:
    cargo clippy -p tranquil-server --no-default-features --features frontend,postgres,s3,valkey --all-targets -- -D warnings
    cargo clippy -p tranquil-pds --no-default-features --all-targets -- -D warnings
fmt:
    cargo fmt
fmt-check:
    cargo fmt -- --check
lint: fmt-check clippy lint-no-bsky

test-store:
    SQLX_OFFLINE=true cargo nextest run -p tranquil-store --features tranquil-store/test-harness

test-store-sim-nightly:
    SQLX_OFFLINE=true TRANQUIL_SIM_SEEDS=10000 cargo nextest run -p tranquil-store --features tranquil-store/test-harness --profile sim-nightly

gauntlet-pr:
    SQLX_OFFLINE=true cargo nextest run -p tranquil-store --features tranquil-store/test-harness --profile gauntlet-pr --test gauntlet_smoke

gauntlet-nightly HOURS="6":
    SQLX_OFFLINE=true GAUNTLET_DURATION_HOURS={{HOURS}} cargo nextest run -p tranquil-store --features tranquil-store/test-harness --profile gauntlet-nightly --test gauntlet_smoke --run-ignored all

gauntlet-farm SCENARIO HOURS="6" DUMP="proptest-regressions":
    SQLX_OFFLINE=true cargo run --release --bin tranquil-gauntlet --features tranquil-store/gauntlet-cli -- farm --scenario {{SCENARIO}} --hours {{HOURS}} --dump-regressions {{DUMP}}

gauntlet-repro SEED SCENARIO="smoke-pr":
    SQLX_OFFLINE=true cargo run --release --bin tranquil-gauntlet --features tranquil-store/gauntlet-cli -- repro --scenario {{SCENARIO}} --seed {{SEED}}

gauntlet-repro-config CONFIG SEED:
    SQLX_OFFLINE=true cargo run --release --bin tranquil-gauntlet --features tranquil-store/gauntlet-cli -- repro --config {{CONFIG}} --seed {{SEED}}

gauntlet-repro-from FILE:
    SQLX_OFFLINE=true cargo run --release --bin tranquil-gauntlet --features tranquil-store/gauntlet-cli -- repro --from {{FILE}}

gauntlet-sweep CONFIG SEEDS="8" DUMP="proptest-regressions":
    SQLX_OFFLINE=true cargo run --release --bin tranquil-gauntlet --features tranquil-store/gauntlet-cli -- sweep --config {{CONFIG}} --seeds {{SEEDS}} --dump-regressions {{DUMP}}

gauntlet-soak HOURS="24" OUTPUT="":
    SQLX_OFFLINE=true GAUNTLET_SOAK_HOURS={{HOURS}} GAUNTLET_SOAK_OUTPUT={{OUTPUT}} cargo nextest run -p tranquil-store --features tranquil-store/test-harness --profile gauntlet-soak --test gauntlet_soak --run-ignored all -- soak_long_leak_gate

gauntlet-soak-heapprof HOURS="24" OUTPUT="" PREFIX="jeprof.gauntlet":
    SQLX_OFFLINE=true \
    GAUNTLET_SOAK_HOURS={{HOURS}} \
    GAUNTLET_SOAK_OUTPUT={{OUTPUT}} \
    MALLOC_CONF="prof:true,prof_active:true,prof_final:true,lg_prof_sample:19,prof_prefix:{{PREFIX}}" \
    cargo nextest run -p tranquil-store \
        --features tranquil-store/test-harness,tranquil-store/gauntlet-jemalloc-prof \
        --profile gauntlet-soak --test gauntlet_soak --run-ignored all -- soak_long_leak_gate

gauntlet-flaky SEED="1":
    SQLX_OFFLINE=true cargo nextest run -p tranquil-store --features tranquil-store/test-harness --test gauntlet_flaky --run-ignored all

fuzz-target TARGET SECONDS="60" SANITIZER="address":
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer {{SANITIZER}} {{TARGET}} -- -max_total_time={{SECONDS}}

fuzz-pr SECONDS="60":
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address decode_block_record -- -max_total_time={{SECONDS}}
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address decode_hint_record -- -max_total_time={{SECONDS}}
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address segment_scan -- -max_total_time={{SECONDS}}
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address metastore_key_codec -- -max_total_time={{SECONDS}}
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address gauntlet_micro -- -max_total_time={{SECONDS}}

fuzz-nightly SECONDS="21600":
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address decode_block_record -- -max_total_time={{SECONDS}}
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address decode_hint_record -- -max_total_time={{SECONDS}}
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address segment_scan -- -max_total_time={{SECONDS}}
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address metastore_key_codec -- -max_total_time={{SECONDS}}
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer address gauntlet_micro -- -max_total_time={{SECONDS}}

fuzz-ubsan TARGET SECONDS="60":
    cd crates/tranquil-store/fuzz && cargo +nightly fuzz run --sanitizer undefined {{TARGET}} -- -max_total_time={{SECONDS}}

test-store-asan:
    SQLX_OFFLINE=true \
        ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:detect_leaks=1" \
        RUSTFLAGS="-Zsanitizer=address" \
        RUSTDOCFLAGS="-Zsanitizer=address" \
        cargo +nightly nextest run -p tranquil-store --features tranquil-store/test-harness --target x86_64-unknown-linux-gnu

test-unit:
    SQLX_OFFLINE=true cargo test --test it -- dpop_unit:: validation_edge_cases:: scope_edge_cases::

store_run := "SQLX_OFFLINE=true TRANQUIL_TEST_BACKEND=store TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=1 DISABLE_RATE_LIMITING=1 TRANQUIL_LEXICON_OFFLINE=1 SKIP_IMPORT_VERIFICATION=true cargo nextest run --workspace --exclude tranquil-store --features tranquil-store/skip-fsync"
store_test := store_run + " -E 'not (binary(it) and test(/^store_parity::/)) and not (package(tranquil-signal) and test(/^tests::/))'"

test-auth:
    {{store_run}} --test it -E 'test(/^(oauth|oauth_lifecycle|oauth_scopes|oauth_security|jwt_security|session_management|change_password|password_reset)::/)'

test-admin:
    {{store_run}} --test it -E 'test(/^(admin_email|admin_invite|admin_moderation|admin_search|admin_stats)::/)'

test-sync:
    {{store_run}} --test it -E 'test(/^(sync_repo|sync_blob|sync_conformance|sync_deprecated|firehose_validation)::/)'

test-repo:
    {{store_run}} --test it -E 'test(/^(repo_batch|repo_blob|record_validation|lifecycle_record)::/)'

test-identity:
    {{store_run}} --test it --test plc_migration -E 'binary(plc_migration) | test(/^(identity|did_web|plc_operations|plc_validation)::/)'

test-account:
    {{store_run}} --test it -E 'test(/^(lifecycle_session|delete_account|invite|email_update|account_notifications)::/)'

test-security:
    {{store_run}} --test it -E 'test(/^(security_fixes|banned_words|rate_limit|moderation)::/)'

test-import:
    {{store_run}} --test it --test import_with_verification -E 'binary(import_with_verification) | test(/^import_verification::/)'

test-misc:
    {{store_run}} --test it -E 'test(/^(actor|commit_signing|image_processing|lifecycle_social|notifications|server|signing_key|verify_live_commit)::/)'

test *args:
    {{store_test}} {{args}}

test-one name:
    {{store_run}} --test it -E 'test(/^{{name}}::/)'

test-full *args:
    @just services-up
    eval "$(tranquil-dev-services env)" && SQLX_OFFLINE=true cargo nextest run --workspace --exclude tranquil-store --features tranquil-pds/s3 {{args}}

test-pg *args:
    SQLX_OFFLINE=true ./scripts/run-tests.sh {{args}}

services-up:
    tranquil-dev-services up

services-down:
    tranquil-dev-services down

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
    podman build -t atcr.io/tranquil.farm/tranquil-pds:latest .
container-pull:
    podman pull atcr.io/tranquil.farm/tranquil-pds:latest

frontend-dev:
    cd frontend && pnpm run dev
frontend-build:
    cd frontend && pnpm run build
frontend-check:
    cd frontend && pnpm run check
frontend-clean:
    rm -rf frontend/dist frontend/node_modules

frontend-test *args:
    cd frontend && VITEST=true pnpm run test:run {{args}}
frontend-test-watch:
    cd frontend && VITEST=true pnpm run test:watch
frontend-test-ui:
    cd frontend && VITEST=true pnpm run test:ui
frontend-test-coverage:
    cd frontend && VITEST=true pnpm run test:run --coverage

build-all: frontend-build build
