FROM rust:1.91.1-alpine AS builder

RUN apk add ca-certificates openssl openssl-dev pkgconfig

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

COPY src ./src
COPY tests ./tests
COPY migrations ./migrations
COPY .sqlx ./.sqlx
RUN touch src/main.rs && cargo build --release

FROM alpine:3.23

COPY --from=builder /app/target/release/bspds /usr/local/bin/bspds
COPY --from=builder /app/migrations /app/migrations

WORKDIR /app

ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=3000

EXPOSE 3000

CMD ["bspds"]
