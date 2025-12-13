# Stage 1: Build frontend with Deno
FROM denoland/deno:alpine AS frontend-builder
WORKDIR /frontend
COPY frontend/ ./
RUN deno task build

# Stage 2: Build Rust backend
FROM rust:1.92-alpine AS builder

RUN apk add ca-certificates openssl openssl-dev pkgconfig

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

COPY src ./src
COPY tests ./tests
COPY migrations ./migrations
COPY .sqlx ./.sqlx
RUN touch src/main.rs && cargo build --release

# Stage 3: Final image
FROM alpine:3.23

COPY --from=builder /app/target/release/bspds /usr/local/bin/bspds
COPY --from=builder /app/migrations /app/migrations
COPY --from=frontend-builder /frontend/dist /app/frontend/dist

WORKDIR /app

ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=3000
ENV FRONTEND_DIR=/app/frontend/dist

EXPOSE 3000

CMD ["bspds"]
