use atomic_float::AtomicF64;
use governor::{state::NotKeyed, NegativeMultiDecision, Quota};

use std::{
    num::NonZeroU32,
    sync::{atomic::Ordering, Arc},
};

pub static BW_MULTIPLIER: AtomicF64 = AtomicF64::new(1.0);

/// A generic rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<
        governor::RateLimiter<
            NotKeyed,
            governor::state::InMemoryState,
            governor::clock::MonotonicClock,
        >,
    >,
    unlimited: bool,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given speed limit, in KB/s
    pub fn new(limit_kb: u32, burst_kb: u32) -> Self {
        let limit = NonZeroU32::new((limit_kb + 1) * 1024).unwrap();
        let burst_size = NonZeroU32::new(burst_kb * 1024).unwrap();
        let inner = governor::RateLimiter::new(
            Quota::per_second(limit).allow_burst(burst_size),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock,
        );
        inner.check_n(burst_size).expect("this should never happen");
        Self {
            inner: Arc::new(inner),
            unlimited: false,
        }
    }

    /// Creates a new unlimited ratelimit.
    pub fn unlimited() -> Self {
        let inner = Arc::new(governor::RateLimiter::new(
            Quota::per_second(NonZeroU32::new(128 * 1024).unwrap()),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock,
        ));
        Self {
            inner,
            unlimited: true,
        }
    }

    /// Waits until the given number of bytes can be let through.
    pub async fn wait(&self, bytes: usize) {
        let bytes = ((bytes as f64) * BW_MULTIPLIER.load(Ordering::Relaxed)) as u32;
        if bytes == 0 || self.unlimited {
            return;
        }

        let bytes = NonZeroU32::new(bytes).unwrap();
        while let Err(err) = self.inner.check_n(bytes) {
            match err {
                NegativeMultiDecision::BatchNonConforming(_, until) => {
                    smol::Timer::at(until.earliest_possible()).await;
                }
                NegativeMultiDecision::InsufficientCapacity(_) => {
                    log::error!("INSUFFICIENT CAP");
                    return;
                }
            }
        }
    }

    /// Checks whether the number of bytes can be let through.
    pub fn check(&self, bytes: usize) -> bool {
        let bytes = ((bytes as f64) * BW_MULTIPLIER.load(Ordering::Relaxed)) as u32;
        if bytes == 0 || self.unlimited {
            return true;
        }

        let bytes = NonZeroU32::new(bytes).unwrap();
        self.inner.check_n(bytes).is_ok()
    }
}
