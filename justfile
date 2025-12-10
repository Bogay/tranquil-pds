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

test:
    cargo test

test-verbose:
    cargo test -- --nocapture

test-repo:
    cargo test --test repo

test-lifecycle:
    cargo test --test lifecycle

test-proxy:
    cargo test --test proxy

test-sync:
    cargo test --test sync

test-server:
    cargo test --test server

test-identity:
    cargo test --test identity

test-auth:
    cargo test --test auth

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
