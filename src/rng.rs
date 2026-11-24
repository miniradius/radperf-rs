//! Small, fast PRNG used for Access-Request authenticators.
//!
//! Seeded from the OS. This is a throughput-oriented generator (xorshift128+),
//! not a cryptographic one; it matches the needs of a load generator. Callers
//! that need unpredictability should supply their own authenticator source.

use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

/// xorshift128+ generator.
pub struct Rng {
    s: [u64; 2],
}

impl Rng {
    /// Seed from the OS entropy pool, falling back to the clock.
    pub fn from_os() -> Rng {
        let mut seed = [0u8; 16];
        let ok = File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut seed))
            .is_ok();
        if !ok {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9e3779b97f4a7c15);
            seed[..8].copy_from_slice(&nanos.to_le_bytes());
            seed[8..].copy_from_slice(&nanos.wrapping_mul(0x2545f4914f6cdd1d).to_le_bytes());
        }
        let mut s = [0u64; 2];
        s[0] = u64::from_le_bytes(seed[..8].try_into().unwrap());
        s[1] = u64::from_le_bytes(seed[8..].try_into().unwrap());
        if s[0] == 0 && s[1] == 0 {
            s[0] = 0x9e3779b97f4a7c15;
        }
        Rng { s }
    }

    /// Construct from an explicit seed (deterministic; useful for tests).
    pub fn from_seed(a: u64, b: u64) -> Rng {
        Rng { s: [a | 1, b] }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.s[0];
        let y = self.s[1];
        self.s[0] = y;
        x ^= x << 23;
        self.s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
        self.s[1].wrapping_add(y)
    }

    /// Fill a buffer with pseudorandom bytes.
    #[inline]
    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= buf.len() {
            buf[i..i + 8].copy_from_slice(&self.next_u64().to_le_bytes());
            i += 8;
        }
        if i < buf.len() {
            let bytes = self.next_u64().to_le_bytes();
            let n = buf.len() - i;
            buf[i..].copy_from_slice(&bytes[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let mut a = Rng::from_seed(1, 2);
        let mut b = Rng::from_seed(1, 2);
        for _ in 0..10 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn fill_is_stable_length_and_changes() {
        let mut r = Rng::from_seed(42, 99);
        let mut buf = [0u8; 20];
        r.fill(&mut buf);
        assert_eq!(buf.len(), 20);
        let first = buf;
        r.fill(&mut buf);
        assert_ne!(first, buf);
    }
}
