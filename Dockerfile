FROM denoland/deno:alpine AS frontend
WORKDIR /app
COPY frontend/ ./
RUN deno task build

FROM rust:1.92-alpine AS builder
RUN apk add --no-cache ca-certificates musl-dev pkgconfig openssl-dev openssl-libs-static
WORKDIR /app
ARG SLIM="false"
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY .sqlx ./.sqlx
COPY migrations ./crates/tranquil-pds/migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    if [ "$SLIM" = "true" ]; then \
      SQLX_OFFLINE=true cargo build --release -p tranquil-pds --no-default-features; \
    else \
      SQLX_OFFLINE=true cargo build --release -p tranquil-pds; \
    fi && \
    cp target/release/tranquil-pds /tmp/tranquil-pds

FROM alpine:3.23 AS signal-cli
RUN apk add --no-cache curl tar
ARG SIGNAL_CLI_VERSION=0.13.24
RUN curl -fsSL "https://github.com/AsamK/signal-cli/releases/download/v${SIGNAL_CLI_VERSION}/signal-cli-${SIGNAL_CLI_VERSION}-Linux-native.tar.gz" \
    | tar xz -C /usr/local/bin

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends msmtp ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/msmtp /usr/sbin/sendmail
COPY --from=signal-cli /usr/local/bin/signal-cli /usr/local/bin/signal-cli
VOLUME /var/lib/signal-cli
COPY --from=builder /tmp/tranquil-pds /usr/local/bin/tranquil-pds
COPY --from=frontend /app/dist /var/lib/tranquil-pds/frontend
COPY migrations /app/migrations
WORKDIR /app
ENV SIGNAL_CLI_CONFIG=/var/lib/signal-cli
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=3000
EXPOSE 3000
CMD ["tranquil-pds"]
