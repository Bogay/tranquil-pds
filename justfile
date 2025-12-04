# Run all tests with correct threading models
test: test-proxy test-lifecycle test-others

# Proxy tests modify environment variables, so must run single-threaded
# TODO: figure out how to run in parallel
test-proxy:
    cargo test --test proxy -- --test-threads=1

# Lifecycle tests involve complex state mutations, run single-threaded to be safe
# TODO: figure out how to run in parallel
test-lifecycle:
    cargo test --test lifecycle -- --test-threads=1

test-others:
    cargo test --lib
    cargo test --test actor
    cargo test --test feed
    cargo test --test graph
    cargo test --test identity
    cargo test --test notification
    cargo test --test repo
    cargo test --test server
    cargo test --test sync
