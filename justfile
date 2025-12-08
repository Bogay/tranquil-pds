# Run all tests
test:
    cargo test

# Run specific test suites if needed
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
