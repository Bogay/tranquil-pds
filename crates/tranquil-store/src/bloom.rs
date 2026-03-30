use xxhash_rust::xxh3::xxh3_64_with_seed;

pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: u64,
    num_hashes: u32,
}

impl BloomFilter {
    const MAX_BITS: u64 = 1 << 34;

    pub fn with_capacity_and_fpr(expected_items: u64, false_positive_rate: f64) -> Self {
        debug_assert!(
            false_positive_rate > 0.0 && false_positive_rate < 1.0,
            "false_positive_rate must be in (0, 1), got {false_positive_rate}"
        );
        let expected = expected_items.max(1) as f64;
        let ln2 = std::f64::consts::LN_2;

        let num_bits_f = -(expected * false_positive_rate.ln()) / (ln2 * ln2);
        let num_bits = num_bits_f.ceil().clamp(64.0, Self::MAX_BITS as f64) as u64;
        let num_bits = num_bits.next_power_of_two();

        let optimal_k = ((num_bits as f64 / expected) * ln2).ceil();
        let num_hashes = (optimal_k as u32).clamp(1, 16);

        let words = (num_bits / 64) as usize;

        Self {
            bits: vec![0u64; words],
            num_bits,
            num_hashes,
        }
    }

    pub fn insert(&mut self, key: &[u8]) {
        let mask = self.num_bits - 1;
        (0..self.num_hashes).for_each(|i| {
            let h = xxh3_64_with_seed(key, u64::from(i)) & mask;
            let word = (h / 64) as usize;
            let bit = h % 64;
            self.bits[word] |= 1u64 << bit;
        });
    }

    pub fn contains(&self, key: &[u8]) -> bool {
        let mask = self.num_bits - 1;
        (0..self.num_hashes).all(|i| {
            let h = xxh3_64_with_seed(key, u64::from(i)) & mask;
            let word = (h / 64) as usize;
            let bit = h % 64;
            (self.bits[word] >> bit) & 1 == 1
        })
    }

    pub fn heap_bytes(&self) -> usize {
        self.bits.len() * 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_contains() {
        let mut bf = BloomFilter::with_capacity_and_fpr(1000, 0.01);
        bf.insert(b"hello");
        bf.insert(b"world");

        assert!(bf.contains(b"hello"));
        assert!(bf.contains(b"world"));
    }

    #[test]
    fn missing_key_usually_absent() {
        let mut bf = BloomFilter::with_capacity_and_fpr(1000, 0.01);
        (0u32..500).for_each(|i| bf.insert(&i.to_le_bytes()));

        let false_positives = (1000u32..2000)
            .filter(|i| bf.contains(&i.to_le_bytes()))
            .count();

        assert!(
            false_positives < 50,
            "expected <5% FPR, got {false_positives}/1000"
        );
    }

    #[test]
    fn no_false_negatives() {
        let mut bf = BloomFilter::with_capacity_and_fpr(10_000, 0.01);
        let keys: Vec<[u8; 4]> = (0u32..10_000).map(|i| i.to_le_bytes()).collect();
        keys.iter().for_each(|k| bf.insert(k));
        assert!(keys.iter().all(|k| bf.contains(k)));
    }

    #[test]
    fn empty_filter_contains_nothing() {
        let bf = BloomFilter::with_capacity_and_fpr(1000, 0.01);
        assert!(!bf.contains(b"anything"));
    }

    #[test]
    fn heap_bytes_reasonable() {
        let bf = BloomFilter::with_capacity_and_fpr(100_000_000, 0.01);
        let mb = bf.heap_bytes() / (1024 * 1024);
        assert!(
            mb < 256,
            "100M items at 1% FPR should be <256MB, got {mb}MB"
        );
        assert!(mb > 64, "100M items at 1% FPR should be >64MB, got {mb}MB");
    }

    #[test]
    fn fpr_empirical() {
        let n = 50_000u32;
        let target_fpr = 0.01;
        let mut bf = BloomFilter::with_capacity_and_fpr(n as u64, target_fpr);

        (0..n).for_each(|i| bf.insert(&i.to_le_bytes()));

        let test_range = 100_000u32;
        let false_positives = (n..n + test_range)
            .filter(|i| bf.contains(&i.to_le_bytes()))
            .count();
        let measured_fpr = false_positives as f64 / test_range as f64;

        assert!(
            measured_fpr < target_fpr * 3.0,
            "measured FPR {measured_fpr:.4} exceeds 3x target {target_fpr}"
        );
    }
}
