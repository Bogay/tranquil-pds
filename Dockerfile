FROM denoland/deno:alpine AS frontend-builder
WORKDIR /frontend
COPY frontend/ ./
RUN deno task build

FROM rust:1.92-alpine AS builder
RUN apk add ca-certificates openssl openssl-dev openssl-libs-static pkgconfig musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY migrations ./migrations
COPY .sqlx ./.sqlx
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/tranquil-pds /tmp/tranquil-pds

FROM alpine:3.23
RUN apk add --no-cache msmtp ca-certificates && ln -sf /usr/bin/msmtp /usr/sbin/sendmail
COPY --from=builder /tmp/tranquil-pds /usr/local/bin/tranquil-pds
COPY --from=builder /app/migrations /app/migrations
COPY --from=frontend-builder /frontend/dist /app/frontend/dist
WORKDIR /app
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=3000
ENV FRONTEND_DIR=/app/frontend/dist
EXPOSE 3000
CMD ["tranquil-pds"]
