use metrics::{counter, gauge, histogram};

pub fn describe_metrics() {
    metrics::describe_gauge!(
        "tranquil_ripple_cache_bytes",
        "Estimated memory used by cache entries"
    );
    metrics::describe_gauge!(
        "tranquil_ripple_rate_limit_bytes",
        "Estimated memory used by rate limit counters"
    );
    metrics::describe_gauge!(
        "tranquil_ripple_gossip_peers",
        "Number of active gossip peers"
    );
    metrics::describe_counter!(
        "tranquil_ripple_cache_hits_total",
        "Total cache read hits"
    );
    metrics::describe_counter!(
        "tranquil_ripple_cache_misses_total",
        "Total cache read misses"
    );
    metrics::describe_counter!(
        "tranquil_ripple_cache_writes_total",
        "Total cache write operations"
    );
    metrics::describe_counter!(
        "tranquil_ripple_cache_deletes_total",
        "Total cache delete operations"
    );
    metrics::describe_counter!(
        "tranquil_ripple_evictions_total",
        "Total cache entries evicted by memory budget"
    );
    metrics::describe_counter!(
        "tranquil_ripple_gossip_deltas_sent_total",
        "Total CRDT delta chunks sent to peers"
    );
    metrics::describe_counter!(
        "tranquil_ripple_gossip_deltas_received_total",
        "Total CRDT delta messages received from peers"
    );
    metrics::describe_counter!(
        "tranquil_ripple_gossip_merges_total",
        "Total CRDT deltas merged with local state change"
    );
    metrics::describe_counter!(
        "tranquil_ripple_gossip_drops_total",
        "Total CRDT deltas dropped (validation or decode failure)"
    );
    metrics::describe_histogram!(
        "tranquil_ripple_gossip_delta_bytes",
        "Size of CRDT delta chunks in bytes"
    );
}

pub fn record_cache_hit() {
    counter!("tranquil_ripple_cache_hits_total").increment(1);
}

pub fn record_cache_miss() {
    counter!("tranquil_ripple_cache_misses_total").increment(1);
}

pub fn record_cache_write() {
    counter!("tranquil_ripple_cache_writes_total").increment(1);
}

pub fn record_cache_delete() {
    counter!("tranquil_ripple_cache_deletes_total").increment(1);
}

pub fn set_cache_bytes(bytes: usize) {
    gauge!("tranquil_ripple_cache_bytes").set(bytes as f64);
}

pub fn set_rate_limit_bytes(bytes: usize) {
    gauge!("tranquil_ripple_rate_limit_bytes").set(bytes as f64);
}

pub fn set_gossip_peers(count: usize) {
    gauge!("tranquil_ripple_gossip_peers").set(count as f64);
}

pub fn record_evictions(count: usize) {
    counter!("tranquil_ripple_evictions_total").increment(count as u64);
}

pub fn record_gossip_delta_sent() {
    counter!("tranquil_ripple_gossip_deltas_sent_total").increment(1);
}

pub fn record_gossip_delta_received() {
    counter!("tranquil_ripple_gossip_deltas_received_total").increment(1);
}

pub fn record_gossip_merge() {
    counter!("tranquil_ripple_gossip_merges_total").increment(1);
}

pub fn record_gossip_drop() {
    counter!("tranquil_ripple_gossip_drops_total").increment(1);
}

pub fn record_gossip_delta_bytes(bytes: usize) {
    histogram!("tranquil_ripple_gossip_delta_bytes").record(bytes as f64);
}
