use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use tranquil_db_traits::{RepoEventType, SequencedEvent};
use tranquil_types::Did;

use tranquil_store::RealIO;
use tranquil_store::eventlog::{
    EventLog, EventLogConfig, EventSequence, decode_payload, to_sequenced_event,
};

fn make_did(index: usize) -> Did {
    let suffix: String = format!("{index:024x}");
    Did::new(format!("did:plc:{suffix}")).unwrap()
}

fn make_event(index: usize) -> SequencedEvent {
    let ops_size = match index % 4 {
        0 => 64,
        1 => 256,
        2 => 1024,
        _ => 4096,
    };

    let ops_payload: String = (0..ops_size)
        .map(|i| ((index.wrapping_mul(31).wrapping_add(i)) % 26 + 97) as u8 as char)
        .collect();

    SequencedEvent {
        seq: tranquil_db_traits::SequenceNumber::from_raw(
            i64::try_from(index + 1).expect("event index overflow"),
        ),
        did: make_did(index % 10_000),
        created_at: Utc::now(),
        event_type: match index % 4 {
            0 => RepoEventType::Commit,
            1 => RepoEventType::Identity,
            2 => RepoEventType::Account,
            _ => RepoEventType::Sync,
        },
        commit_cid: None,
        prev_cid: None,
        prev_data_cid: None,
        ops: Some(serde_json::json!({ "data": ops_payload })),
        blobs: None,
        blocks: None,
        handle: None,
        active: None,
        status: None,
        rev: None,
    }
}

fn open_eventlog(dir: &Path) -> EventLog<RealIO> {
    let segments_dir = dir.join("segments");
    std::fs::create_dir_all(&segments_dir).unwrap();
    EventLog::open(
        EventLogConfig {
            segments_dir,
            ..EventLogConfig::default()
        },
        RealIO::new(),
    )
    .unwrap()
}

struct PhaseTimings {
    raw_read_ns: Vec<u64>,
    decode_payload_ns: Vec<u64>,
    ops_json_ns: Vec<u64>,
    did_parse_ns: Vec<u64>,
    full_conversion_ns: Vec<u64>,
    total_get_events_ns: Vec<u64>,
}

impl PhaseTimings {
    fn new(capacity: usize) -> Self {
        Self {
            raw_read_ns: Vec::with_capacity(capacity),
            decode_payload_ns: Vec::with_capacity(capacity),
            ops_json_ns: Vec::with_capacity(capacity),
            did_parse_ns: Vec::with_capacity(capacity),
            full_conversion_ns: Vec::with_capacity(capacity),
            total_get_events_ns: Vec::with_capacity(capacity),
        }
    }
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * pct / 100.0) as usize;
    sorted[idx]
}

fn report_phase(name: &str, values_ns: &mut [u64], event_count: usize) {
    values_ns.sort();
    let total: u64 = values_ns.iter().sum();
    let per_event_ns = total as f64 / event_count as f64;
    let p50 = percentile(values_ns, 50.0);
    let p99 = percentile(values_ns, 99.0);
    println!(
        "{name}: {:.2}ms total, {per_event_ns:.0}ns/event, p50 {p50}ns, p99 {p99}ns",
        total as f64 / 1_000_000.0,
    );
}

fn profile_read_phases(event_count: usize, readers: usize) {
    println!("-- read path profile: {event_count} events, {readers} readers --");

    let dir = tempfile::TempDir::new().unwrap();
    let log = Arc::new(open_eventlog(dir.path()));

    let events: Vec<SequencedEvent> = (0..event_count).map(make_event).collect();
    events.iter().enumerate().for_each(|(i, event)| {
        log.append_event(&make_did(i % 10_000), RepoEventType::Commit, event)
            .unwrap();
    });
    log.sync().unwrap();

    println!("seeded {event_count} events");

    let batch_size = 4096usize;
    let iterations = 3;

    (0..iterations).for_each(|iter| {
        println!("-- iteration {}/{iterations} --", iter + 1);

        let handles: Vec<_> = (0..readers)
            .map(|_| {
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    let reader = log.reader();
                    let mut timings = PhaseTimings::new(event_count / batch_size + 1);
                    let mut total_events = 0usize;

                    let mut cursor = EventSequence::BEFORE_ALL;
                    std::iter::from_fn(|| {
                        let t_total = Instant::now();

                        let t_raw = Instant::now();
                        let raw_events = reader.read_events_from(cursor, batch_size).unwrap();
                        let raw_read_elapsed = t_raw.elapsed();

                        if raw_events.is_empty() {
                            return None;
                        }

                        let mut batch_decode_ns = 0u64;
                        let mut batch_ops_ns = 0u64;
                        let mut batch_did_ns = 0u64;
                        let mut batch_conversion_ns = 0u64;

                        raw_events.iter().for_each(|raw| {
                            let t_decode = Instant::now();
                            let payload = decode_payload(&raw.payload).unwrap();
                            batch_decode_ns += t_decode.elapsed().as_nanos() as u64;

                            let t_ops = Instant::now();
                            let _ops: Option<serde_json::Value> = payload
                                .ops
                                .as_ref()
                                .map(|bytes| serde_ipld_dagcbor::from_slice(bytes).unwrap());
                            batch_ops_ns += t_ops.elapsed().as_nanos() as u64;

                            let t_did = Instant::now();
                            let _did = Did::new(&payload.did).unwrap();
                            batch_did_ns += t_did.elapsed().as_nanos() as u64;

                            let t_conversion = Instant::now();
                            let payload2 = decode_payload(&raw.payload).unwrap();
                            let _event = to_sequenced_event(raw, &payload2).unwrap();
                            batch_conversion_ns += t_conversion.elapsed().as_nanos() as u64;
                        });

                        let batch_events = raw_events.len();
                        cursor = EventSequence::new(
                            u64::try_from(raw_events.last().unwrap().seq.as_i64()).unwrap(),
                        );
                        total_events += batch_events;

                        timings.raw_read_ns.push(raw_read_elapsed.as_nanos() as u64);
                        timings.decode_payload_ns.push(batch_decode_ns);
                        timings.ops_json_ns.push(batch_ops_ns);
                        timings.did_parse_ns.push(batch_did_ns);
                        timings.full_conversion_ns.push(batch_conversion_ns);
                        timings
                            .total_get_events_ns
                            .push(t_total.elapsed().as_nanos() as u64);

                        Some(())
                    })
                    .count();

                    (timings, total_events)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let total_events: usize = results.iter().map(|(_, count)| count).sum();

        let mut agg = PhaseTimings::new(0);
        results.iter().for_each(|(t, _)| {
            agg.raw_read_ns.extend_from_slice(&t.raw_read_ns);
            agg.decode_payload_ns
                .extend_from_slice(&t.decode_payload_ns);
            agg.ops_json_ns.extend_from_slice(&t.ops_json_ns);
            agg.did_parse_ns.extend_from_slice(&t.did_parse_ns);
            agg.full_conversion_ns
                .extend_from_slice(&t.full_conversion_ns);
            agg.total_get_events_ns
                .extend_from_slice(&t.total_get_events_ns);
        });

        println!("{total_events} events across {readers} readers");
        report_phase("raw_read", &mut agg.raw_read_ns, total_events);
        report_phase("full conversion", &mut agg.full_conversion_ns, total_events);
        report_phase(
            "postcard decode, isolated",
            &mut agg.decode_payload_ns,
            total_events,
        );
        report_phase(
            "DAG-CBOR ops parse, isolated",
            &mut agg.ops_json_ns,
            total_events,
        );
        report_phase("DID parse, isolated", &mut agg.did_parse_ns, total_events);
        report_phase(
            "end-to-end total",
            &mut agg.total_get_events_ns,
            total_events,
        );

        let raw_total: u64 = agg.raw_read_ns.iter().sum();
        let conversion_total: u64 = agg.full_conversion_ns.iter().sum();
        let decode_total: u64 = agg.decode_payload_ns.iter().sum();
        let ops_total: u64 = agg.ops_json_ns.iter().sum();
        let did_total: u64 = agg.did_parse_ns.iter().sum();

        let pipeline_total = raw_total + conversion_total;
        let pct = |v: u64| v as f64 / pipeline_total as f64 * 100.0;
        let conversion_other =
            conversion_total.saturating_sub(decode_total + ops_total + did_total);
        println!(
            "breakdown: raw_read {:.1}%, postcard {:.1}%, dagcbor_ops {:.1}%, did {:.1}%, rest {:.1}%",
            pct(raw_total),
            pct(decode_total),
            pct(ops_total),
            pct(did_total),
            pct(conversion_other),
        );
    });

    let _ = log.shutdown();
}

fn profile_decode_phases(event_count: usize) {
    println!("-- decode phase isolation: {event_count} events --");

    let dir = tempfile::TempDir::new().unwrap();
    let log = open_eventlog(dir.path());

    let events: Vec<SequencedEvent> = (0..event_count).map(make_event).collect();
    events.iter().enumerate().for_each(|(i, event)| {
        log.append_event(&make_did(i % 10_000), RepoEventType::Commit, event)
            .unwrap();
    });
    log.sync().unwrap();

    let reader = log.reader();
    let raw_events = reader
        .read_events_from(EventSequence::BEFORE_ALL, event_count)
        .unwrap();

    println!("{} raw events pre-loaded", raw_events.len());

    (0..5).for_each(|_| {
        let t_decode = Instant::now();
        let payloads: Vec<_> = raw_events
            .iter()
            .map(|raw| decode_payload(&raw.payload).unwrap())
            .collect();
        let decode_elapsed = t_decode.elapsed();

        let t_convert = Instant::now();
        let _events: Vec<_> = raw_events
            .iter()
            .zip(payloads.iter())
            .map(|(raw, payload)| to_sequenced_event(raw, payload).unwrap())
            .collect();
        let convert_elapsed = t_convert.elapsed();

        let t_ops_only = Instant::now();
        let _: Vec<_> = payloads
            .iter()
            .map(|p| {
                p.ops.as_ref().map(|bytes| {
                    serde_ipld_dagcbor::from_slice::<serde_json::Value>(bytes).unwrap()
                })
            })
            .collect();
        let ops_elapsed = t_ops_only.elapsed();

        let n = raw_events.len() as f64;
        println!(
            "postcard {:.0}ns/evt, to_sequenced_event {:.0}ns/evt, dagcbor_ops {:.0}ns/evt",
            decode_elapsed.as_nanos() as f64 / n,
            convert_elapsed.as_nanos() as f64 / n,
            ops_elapsed.as_nanos() as f64 / n,
        );
    });

    let _ = log.shutdown();
}

fn main() {
    println!("-- eventlog read path profiler --");
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    println!("available parallelism: {cpus}");

    let event_count = std::env::var("PROFILE_EVENTS")
        .ok()
        .and_then(|s| s.replace('_', "").parse().ok())
        .unwrap_or(100_000usize);

    let reader_count = std::env::var("PROFILE_READERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4usize);

    profile_read_phases(event_count, reader_count);
    println!();
    profile_decode_phases(event_count);
}
