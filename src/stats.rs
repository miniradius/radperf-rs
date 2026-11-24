//! Counters and latency histograms.
//!
//! The histogram uses 8-bit-mantissa logarithmic buckets (the same idea as an
//! HDR histogram): a fixed, preallocated array, O(1) recording, no allocation
//! on the hot path. Sub-microsecond resolution for the first 256 us and ~0.5 %
//! relative resolution above.

/// Number of buckets: 256 linear + 57 octaves x 128 sub-buckets (indices for
/// `e` from 8 to 63 inclusive).
const BUCKETS: usize = 256 + 57 * 128;

/// A fixed-size latency histogram in microseconds.
#[derive(Clone)]
pub struct Histogram {
    buckets: Vec<u64>,
    count: u64,
    sum: u128,
    min: u64,
    max: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram::new()
    }
}

impl Histogram {
    pub fn new() -> Histogram {
        Histogram {
            buckets: vec![0; BUCKETS],
            count: 0,
            sum: 0,
            min: u64::MAX,
            max: 0,
        }
    }

    #[inline]
    fn bucket_index(v: u64) -> usize {
        if v < 256 {
            v as usize
        } else {
            let e = 63 - v.leading_zeros() as usize; // floor(log2 v), >= 8
            let m = (v >> (e - 7)) as usize; // 8-bit mantissa in 128..=255
            256 + (e - 7) * 128 + (m - 128)
        }
    }

    fn bucket_lower(index: usize) -> u64 {
        if index < 256 {
            index as u64
        } else {
            let k = index - 256;
            let e = 7 + k / 128;
            let m = 128 + k % 128;
            (m as u64) << (e - 7)
        }
    }

    /// Record one sample in microseconds.
    #[inline]
    pub fn record(&mut self, micros: u64) {
        self.buckets[Self::bucket_index(micros)] += 1;
        self.count += 1;
        self.sum += micros as u128;
        if micros < self.min {
            self.min = micros;
        }
        if micros > self.max {
            self.max = micros;
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn min(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.min
        }
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum as f64 / self.count as f64
        }
    }

    /// Approximate percentile in microseconds (lower bucket bound).
    pub fn percentile(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let target = (p.clamp(0.0, 1.0) * self.count as f64).ceil() as u64;
        let mut acc = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            acc += c;
            if acc >= target {
                return Self::bucket_lower(i);
            }
        }
        self.max
    }

    /// Merge another histogram into this one.
    pub fn merge(&mut self, other: &Histogram) {
        for (a, b) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *a += *b;
        }
        self.count += other.count;
        self.sum += other.sum;
        if other.count > 0 {
            self.min = self.min.min(other.min);
            self.max = self.max.max(other.max);
        }
    }
}

/// Response-time histogram labels, in order (matches the reference tool).
/// The reference prints eight buckets; the first decade name (`usec`) is not
/// shown.
pub const DECADE_NAMES: [&str; 8] = [
    "10 usec", "100 usec", "msec", "10 msec", "0.1s", "s", "10s", "100s",
];

/// Upper bounds (microseconds) for the response-time buckets.
const DECADE_BOUNDS: [u64; 8] = [
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
];

/// Aggregate counters for a run.
#[derive(Clone, Default)]
pub struct Stats {
    /// Requests whose first attempt was sent successfully.
    pub requests_sent: u64,
    pub responses_received: u64,
    /// Additional datagrams sent for requests still awaiting a response.
    pub retransmits: u64,
    /// Requests that exhausted their attempts without a verified response.
    pub timeouts: u64,
    pub malformed: u64,
    pub unmatched: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    // Responses by RADIUS code.
    pub access_accept: u64,
    pub access_reject: u64,
    pub access_challenge: u64,
    pub accounting_response: u64,
    pub coa_ack: u64,
    pub coa_nak: u64,
    pub disconnect_ack: u64,
    pub disconnect_nak: u64,
    pub other_responses: u64,
    /// Time from the first attempt to a verified response, including retries.
    pub rtt: Histogram,
    /// Response times bucketed by decade, for the summary and JSON output.
    pub decades: [u64; 8],
    /// Inter-request send delay, as reported by `-D`.
    pub send_delay: Histogram,
}

impl Stats {
    pub fn new() -> Stats {
        Stats::default()
    }

    /// Tally a verified response by its packet code.
    pub fn record_response_code(&mut self, code: u8) {
        match code {
            crate::packet::ACCESS_ACCEPT => self.access_accept += 1,
            crate::packet::ACCESS_REJECT => self.access_reject += 1,
            crate::packet::ACCESS_CHALLENGE => self.access_challenge += 1,
            crate::packet::ACCOUNTING_RESPONSE => self.accounting_response += 1,
            crate::packet::COA_ACK => self.coa_ack += 1,
            crate::packet::COA_NAK => self.coa_nak += 1,
            crate::packet::DISCONNECT_ACK => self.disconnect_ack += 1,
            crate::packet::DISCONNECT_NAK => self.disconnect_nak += 1,
            _ => self.other_responses += 1,
        }
    }

    /// Bucket a round-trip time (microseconds) into the decade histogram.
    pub fn record_decade(&mut self, micros: u64) {
        let mut index = DECADE_BOUNDS.len() - 1;
        for (i, bound) in DECADE_BOUNDS.iter().enumerate() {
            if micros < *bound {
                index = i;
                break;
            }
        }
        self.decades[index] += 1;
    }

    /// Responses that indicate success (Accept / Response / ACK).
    pub fn total_succeeded(&self) -> u64 {
        self.access_accept + self.accounting_response + self.coa_ack + self.disconnect_ack
    }

    /// Responses that indicate failure (Reject / NAK).
    pub fn total_failed(&self) -> u64 {
        self.access_reject + self.coa_nak + self.disconnect_nak
    }

    /// Loss rate as a fraction of sent requests.
    pub fn loss_ratio(&self) -> f64 {
        if self.requests_sent == 0 {
            0.0
        } else {
            1.0 - (self.responses_received as f64 / self.requests_sent as f64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_histogram() {
        let h = Histogram::new();
        assert_eq!(h.count(), 0);
        assert_eq!(h.min(), 0);
        assert_eq!(h.mean(), 0.0);
        assert_eq!(h.percentile(0.99), 0);
    }

    #[test]
    fn records_min_max_mean() {
        let mut h = Histogram::new();
        for v in [10u64, 20, 30, 40, 50] {
            h.record(v);
        }
        assert_eq!(h.count(), 5);
        assert_eq!(h.min(), 10);
        assert_eq!(h.max(), 50);
        assert_eq!(h.mean(), 30.0);
    }

    #[test]
    fn percentile_is_within_bucket_of_true_value() {
        let mut h = Histogram::new();
        for i in 1..=1000u64 {
            h.record(i * 100); // 100..100_000 us
        }
        let p50 = h.percentile(0.50);
        // 50th percentile true value is ~50_000 us; allow 1% bucket error.
        assert!(p50.abs_diff(50_000) <= 500, "p50={p50}");
        let p99 = h.percentile(0.99);
        assert!(p99.abs_diff(99_000) <= 1_000, "p99={p99}");
    }

    #[test]
    fn large_values_do_not_panic() {
        let mut h = Histogram::new();
        h.record(u64::MAX);
        h.record(0);
        assert_eq!(h.count(), 2);
    }

    #[test]
    fn merge_combines() {
        let mut a = Histogram::new();
        let mut b = Histogram::new();
        a.record(100);
        b.record(200);
        a.merge(&b);
        assert_eq!(a.count(), 2);
        assert_eq!(a.min(), 100);
        assert_eq!(a.max(), 200);
    }
}
