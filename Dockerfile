ARG DISTROLESS_IMAGE=gcr.io/distroless/cc-debian13:latest@sha256:a017e74bd2a12d98342dbecd33d121d2b160415ed777573dc1808969e989d94d

FROM node:24-trixie-slim AS frontend
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM rust:1.96-slim-trixie AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates pkg-config libssl-dev mold clang protobuf-compiler curl xz-utils \
    && rm -rf /var/lib/apt/lists/*
ARG COMPRESS="true"
RUN set -eux; \
    if [ "$COMPRESS" = "true" ]; then \
      arch="$(uname -m)"; \
      case "$arch" in \
        x86_64)  upx_arch=amd64; upx_sha=ddc2654063fe4dc80d95b420788494e4db078ebb01a650692d623b5a9906e61e ;; \
        aarch64) upx_arch=arm64; upx_sha=100310f74eb6f67694d1d0377f1c729b6a49238ce8c4de21ea2e7d3406186f8b ;; \
        *) echo "upx: no prebuilt binary for $arch, skipping compression"; upx_arch="" ;; \
      esac; \
      if [ -n "$upx_arch" ]; then \
        curl -fsSL -o /tmp/upx.tar.xz "https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-${upx_arch}_linux.tar.xz"; \
        echo "${upx_sha}  /tmp/upx.tar.xz" | sha256sum -c -; \
        tar -xJf /tmp/upx.tar.xz -C /tmp; \
        install -m0755 "/tmp/upx-5.0.2-${upx_arch}_linux/upx" /usr/local/bin/upx; \
        rm -rf /tmp/upx.tar.xz "/tmp/upx-5.0.2-${upx_arch}_linux"; \
      fi; \
    fi
RUN mkdir -p /stage/var/lib/tranquil-pds/blobs /stage/var/lib/tranquil-pds/store
ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=mold"
WORKDIR /app
ARG SLIM="false"
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS
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
    cp target/release/tranquil-server /tmp/tranquil-pds && \
    if [ "$COMPRESS" = "true" ] && command -v upx >/dev/null 2>&1; then upx --best --lzma /tmp/tranquil-pds; fi

FROM ${DISTROLESS_IMAGE}
COPY --from=builder /tmp/tranquil-pds /usr/local/bin/tranquil-pds
COPY --from=builder --chown=65532:65532 /stage/var/lib/tranquil-pds /var/lib/tranquil-pds
COPY --from=frontend --chown=65532:65532 /app/dist /var/lib/tranquil-pds/frontend
WORKDIR /var/lib/tranquil-pds
ENV SERVER_HOST=[::]
ENV SERVER_PORT=3000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/tranquil-pds"]
