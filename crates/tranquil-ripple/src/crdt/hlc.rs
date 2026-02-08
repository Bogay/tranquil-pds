use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HlcTimestamp {
    pub wall_ms: u64,
    pub counter: u32,
    pub node_id: u64,
}

impl HlcTimestamp {
    pub const ZERO: Self = Self {
        wall_ms: 0,
        counter: 0,
        node_id: 0,
    };
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.wall_ms
            .cmp(&other.wall_ms)
            .then(self.counter.cmp(&other.counter))
            .then(self.node_id.cmp(&other.node_id))
    }
}

fn advance_counter(wall: u64, counter: u32) -> (u64, u32) {
    match counter == u32::MAX {
        true => (wall.saturating_add(1), 0),
        false => (wall, counter + 1),
    }
}

pub struct Hlc {
    node_id: u64,
    last_wall_ms: u64,
    last_counter: u32,
}

impl Hlc {
    pub fn new(node_id: u64) -> Self {
        Self {
            node_id,
            last_wall_ms: 0,
            last_counter: 0,
        }
    }

    fn physical_now() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }

    pub fn now(&mut self) -> HlcTimestamp {
        let phys = Self::physical_now();
        let (wall, counter) = match phys > self.last_wall_ms {
            true => (phys, 0u32),
            false => advance_counter(self.last_wall_ms, self.last_counter),
        };
        self.last_wall_ms = wall;
        self.last_counter = counter;
        HlcTimestamp {
            wall_ms: wall,
            counter,
            node_id: self.node_id,
        }
    }

    pub fn receive(&mut self, remote: HlcTimestamp) -> HlcTimestamp {
        let phys = Self::physical_now();
        let max_allowed = phys + 60_000;
        let capped_remote_wall = remote.wall_ms.min(max_allowed);
        if remote.wall_ms > max_allowed {
            tracing::warn!(
                remote_wall_ms = remote.wall_ms,
                local_wall_ms = phys,
                drift_ms = remote.wall_ms.saturating_sub(phys),
                capped_to = max_allowed,
                "remote HLC wall clock >60s ahead, capping"
            );
        }
        let remote_counter = match capped_remote_wall == remote.wall_ms {
            true => remote.counter,
            false => 0u32,
        };
        let max_wall = phys.max(self.last_wall_ms).max(capped_remote_wall);
        let (wall, counter) = match max_wall {
            w if w == phys && w > self.last_wall_ms && w > capped_remote_wall => (w, 0u32),
            w if w == self.last_wall_ms && w == capped_remote_wall => {
                advance_counter(w, self.last_counter.max(remote_counter))
            }
            w if w == self.last_wall_ms => advance_counter(w, self.last_counter),
            w if w == capped_remote_wall => advance_counter(w, remote_counter),
            w => (w, 0u32),
        };
        self.last_wall_ms = wall;
        self.last_counter = counter;
        HlcTimestamp {
            wall_ms: wall,
            counter,
            node_id: self.node_id,
        }
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonicity() {
        let mut hlc = Hlc::new(1);
        let timestamps: Vec<HlcTimestamp> = (0..100).map(|_| hlc.now()).collect();
        timestamps.windows(2).for_each(|w| {
            assert!(w[1] > w[0], "timestamps must be strictly increasing");
        });
    }

    #[test]
    fn merge_takes_max_within_drift_cap() {
        let mut hlc = Hlc::new(1);
        let now = Hlc::physical_now();
        let remote = HlcTimestamp {
            wall_ms: now + 5000,
            counter: 10,
            node_id: 2,
        };
        let merged = hlc.receive(remote);
        assert!(merged.wall_ms >= remote.wall_ms);
        let after = hlc.now();
        assert!(after > merged);
    }

    #[test]
    fn drift_cap_limits_remote_wall() {
        let mut hlc = Hlc::new(1);
        let now = Hlc::physical_now();
        let remote = HlcTimestamp {
            wall_ms: now + 120_000,
            counter: 50,
            node_id: 2,
        };
        let merged = hlc.receive(remote);
        assert!(merged.wall_ms <= now + 60_000 + 1);
        let after = hlc.now();
        assert!(after > merged);
    }

    #[test]
    fn total_order_across_nodes() {
        let a = HlcTimestamp {
            wall_ms: 100,
            counter: 0,
            node_id: 1,
        };
        let b = HlcTimestamp {
            wall_ms: 100,
            counter: 0,
            node_id: 2,
        };
        assert!(a < b);
        assert_ne!(a, b);
    }

    #[test]
    fn counter_overflow_bumps_wall() {
        let mut hlc = Hlc::new(1);
        let future_wall = u64::MAX / 2;
        hlc.last_wall_ms = future_wall;
        hlc.last_counter = u32::MAX;
        let ts = hlc.now();
        assert_eq!(ts.wall_ms, future_wall + 1);
        assert_eq!(ts.counter, 0);
        let ts2 = hlc.now();
        assert!(ts2 > ts);
    }

    #[test]
    fn receive_counter_overflow_bumps_wall() {
        let mut hlc = Hlc::new(1);
        let future_wall = u64::MAX / 2;
        hlc.last_wall_ms = future_wall;
        hlc.last_counter = u32::MAX;
        let remote = HlcTimestamp {
            wall_ms: future_wall,
            counter: u32::MAX,
            node_id: 2,
        };
        let merged = hlc.receive(remote);
        assert_eq!(merged.wall_ms, future_wall + 1);
        assert_eq!(merged.counter, 0);
    }
}
