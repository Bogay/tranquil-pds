FROM rust:1.92-alpine AS builder
RUN apk add --no-cache ca-certificates openssl openssl-dev openssl-libs-static pkgconfig musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY .sqlx ./.sqlx
COPY migrations ./crates/tranquil-pds/migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    SQLX_OFFLINE=true cargo build --release -p tranquil-pds && \
    cp target/release/tranquil-pds /tmp/tranquil-pds

FROM alpine:3.23
RUN apk add --no-cache msmtp ca-certificates && ln -sf /usr/bin/msmtp /usr/sbin/sendmail
COPY --from=builder /tmp/tranquil-pds /usr/local/bin/tranquil-pds
COPY migrations /app/migrations
WORKDIR /app
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=3000
EXPOSE 3000
CMD ["tranquil-pds"]
