//! Reconnect policy: jittered exponential backoff, what each close code means, and a clock that tests
//! can replace.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Sleeping, behind a trait so tests can run the reconnect loop on a fake clock.
pub trait Clock: Send + Sync {
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

/// The real clock (tokio's timer).
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioClock;

impl Clock for TokioClock {
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// SplitMix64: a tiny, seedable generator for jitter (not for anything secret).
#[derive(Debug, Clone)]
pub struct Jitter(u64);

impl Jitter {
    pub fn new(seed: u64) -> Self {
        Jitter(seed)
    }

    /// Seeded from the OS, so many clients restarted together don't reconnect in step.
    pub fn from_entropy() -> Self {
        let mut b = [0u8; 8];
        let _ = getrandom::fill(&mut b);
        Jitter(u64::from_le_bytes(b))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `lo..=hi` milliseconds.
    pub fn between(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo + 1)
    }
}

/// Exponential backoff with jitter: attempt `n` waits a random time in `[max(min, d/2), d]` where
/// `d = min(max, base · 2ⁿ)`. `base` starts at `min` and follows the stream's `retry:` field.
#[derive(Debug, Clone)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    base: Duration,
    attempt: u32,
    jitter: Jitter,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration, jitter: Jitter) -> Self {
        Backoff {
            min,
            max,
            base: min,
            attempt: 0,
            jitter,
        }
    }

    /// The stream's `retry:` value becomes the base delay (kept within `min..=max`).
    pub fn set_base(&mut self, retry: Duration) {
        self.base = retry.clamp(self.min, self.max);
    }

    /// Consecutive failed attempts so far.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// A healthy stream (one that said `ready`) starts the sequence again.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// The delay before the next attempt.
    pub fn next_delay(&mut self) -> Duration {
        let factor = 1u32 << self.attempt.min(16);
        let ceiling = self.base.saturating_mul(factor).min(self.max);
        let floor = (ceiling / 2).max(self.min).min(ceiling);
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_millis(
            self.jitter
                .between(floor.as_millis() as u64, ceiling.as_millis() as u64),
        )
    }
}

/// What a `closed` code tells the client to do (PROTOCOL §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAction {
    /// Terminal: `4401` (revoked) and `4409` (replaced by a newer stream).
    Stop,
    /// `4408` (too slow to read): reconnect at once.
    ReconnectNow,
    /// `1012` (restarting) and anything else: reconnect after the backoff, with jitter.
    Reconnect,
}

pub fn close_action(code: u16) -> CloseAction {
    match code {
        4401 | 4409 => CloseAction::Stop,
        4408 => CloseAction::ReconnectNow,
        _ => CloseAction::Reconnect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A fake clock: sleeping returns at once and adds to virtual time.
    #[derive(Default, Clone)]
    struct FakeClock {
        slept: Arc<Mutex<Vec<Duration>>>,
    }

    impl Clock for FakeClock {
        fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            self.slept.lock().unwrap().push(d);
            Box::pin(std::future::ready(()))
        }
    }

    impl FakeClock {
        fn total(&self) -> Duration {
            self.slept.lock().unwrap().iter().sum()
        }
    }

    const S: Duration = Duration::from_secs(1);

    fn backoff(seed: u64) -> Backoff {
        Backoff::new(S, 30 * S, Jitter::new(seed))
    }

    #[test]
    fn delays_grow_from_one_second_to_thirty_with_jitter() {
        for seed in 0..200 {
            let mut b = backoff(seed);
            let bounds = [(1, 1), (1, 2), (2, 4), (4, 8), (8, 16), (15, 30), (15, 30)];
            for (n, (lo, hi)) in bounds.iter().enumerate() {
                let d = b.next_delay();
                assert!(
                    d >= *lo * S && d <= *hi * S,
                    "seed {seed} attempt {n}: {d:?} not in {lo}..={hi} s"
                );
            }
            for _ in 0..50 {
                let d = b.next_delay();
                assert!(d >= 15 * S && d <= 30 * S);
            }
        }
    }

    #[test]
    fn jitter_spreads_clients_apart() {
        let firsts: std::collections::HashSet<_> = (0..50)
            .map(|seed| {
                let mut b = backoff(seed);
                b.next_delay();
                b.next_delay()
            })
            .collect();
        assert!(
            firsts.len() > 10,
            "only {} distinct second delays",
            firsts.len()
        );
    }

    #[test]
    fn retry_field_sets_the_base_within_bounds() {
        let mut b = backoff(1);
        b.set_base(Duration::from_millis(5000));
        let d = b.next_delay();
        assert!(d >= Duration::from_millis(2500) && d <= 5 * S, "{d:?}");
        let mut b = backoff(1);
        b.set_base(Duration::from_millis(10));
        assert_eq!(b.next_delay(), S);
        let mut b = backoff(1);
        b.set_base(Duration::from_secs(600));
        assert!(b.next_delay() <= 30 * S);
    }

    #[tokio::test]
    async fn a_fake_clock_drives_a_reconnect_sequence() {
        // Ten failed attempts, a healthy stream, then another failure: the waits are what the
        // policy says, the cap holds, and `ready` resets the sequence to about one second.
        let clock = FakeClock::default();
        let mut b = backoff(7);
        for _ in 0..10 {
            clock.sleep(b.next_delay()).await;
        }
        let total = clock.total();
        assert!(
            total >= (1 + 1 + 2 + 4 + 8 + 15 * 5) * S && total <= 300 * S,
            "{total:?}"
        );
        assert!(clock.slept.lock().unwrap().iter().all(|d| *d <= 30 * S));
        b.reset();
        assert_eq!(b.attempt(), 0);
        clock.sleep(b.next_delay()).await;
        assert_eq!(*clock.slept.lock().unwrap().last().unwrap(), S);
    }

    #[test]
    fn close_codes_map_to_the_protocol_table() {
        assert_eq!(close_action(4401), CloseAction::Stop);
        assert_eq!(close_action(4409), CloseAction::Stop);
        assert_eq!(close_action(4408), CloseAction::ReconnectNow);
        assert_eq!(close_action(1012), CloseAction::Reconnect);
        assert_eq!(close_action(1000), CloseAction::Reconnect);
    }
}
