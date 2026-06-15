FROM node:24-trixie-slim AS frontend
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM rust:1.96-slim-trixie AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates pkg-config libssl-dev mold clang protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=mold"
WORKDIR /app
ARG SLIM="false"
COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx
COPY crates/tranquil-types ./crates/tranquil-types
COPY crates/tranquil-crypto ./crates/tranquil-crypto
COPY crates/tranquil-scopes ./crates/tranquil-scopes
COPY crates/tranquil-config ./crates/tranquil-config
COPY crates/tranquil-repo ./crates/tranquil-repo
COPY crates/tranquil-lexicon ./crates/tranquil-lexicon
COPY crates/tranquil-oauth ./crates/tranquil-oauth
COPY crates/tranquil-db-traits ./crates/tranquil-db-traits
COPY crates/tranquil-infra ./crates/tranquil-infra
COPY crates/tranquil-auth ./crates/tranquil-auth
COPY crates/tranquil-comms ./crates/tranquil-comms
COPY crates/tranquil-db ./crates/tranquil-db
COPY crates/tranquil-ripple ./crates/tranquil-ripple
COPY crates/tranquil-storage ./crates/tranquil-storage
COPY crates/tranquil-cache ./crates/tranquil-cache
COPY crates/tranquil-pds ./crates/tranquil-pds
COPY crates/tranquil-sync ./crates/tranquil-sync
COPY crates/tranquil-api ./crates/tranquil-api
COPY crates/tranquil-oauth-server ./crates/tranquil-oauth-server
COPY crates/tranquil-store ./crates/tranquil-store
COPY crates/tranquil-signal ./crates/tranquil-signal
COPY crates/tranquil-server ./crates/tranquil-server
COPY migrations ./migrations
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=tranquil-target,target=/app/target,sharing=locked \
    if [ "$SLIM" = "true" ]; then \
      SQLX_OFFLINE=true cargo build --release -p tranquil-server --no-default-features; \
    else \
      SQLX_OFFLINE=true cargo build --release -p tranquil-server; \
    fi && \
    cp target/release/tranquil-server /tmp/tranquil-pds

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/tranquil-pds /usr/local/bin/tranquil-pds
COPY --from=frontend /app/dist /var/lib/tranquil-pds/frontend
WORKDIR /app
ENV SERVER_HOST=[::]
ENV SERVER_PORT=3000
EXPOSE 3000
CMD ["tranquil-pds"]
