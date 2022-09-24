use std::num::NonZeroU32;

use governor::{state::NotKeyed, NegativeMultiDecision, Quota};

/// A generic rate limiter.
pub struct RateLimiter {
    inner: governor::RateLimiter<
        NotKeyed,
        governor::state::InMemoryState,
        governor::clock::MonotonicClock,
    >,
    unlimited: bool,
    limit: u32,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given speed limit, in KB/s
    pub fn new(l: u32) -> Self {
        let limit = NonZeroU32::new(l * 1024).unwrap();
        let inner = governor::RateLimiter::new(
            Quota::per_second(limit).allow_burst(NonZeroU32::new(l * 256).unwrap()),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        );
        Self {
            inner,
            unlimited: false,
            limit: l,
        }
    }

    /// Creates a new unlimited ratelimit.
    pub fn unlimited() -> Self {
        let inner = governor::RateLimiter::new(
            Quota::per_second(NonZeroU32::new(128 * 1024).unwrap()),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        );
        Self {
            inner,
            unlimited: true,
            limit: u32::MAX,
        }
    }

    /// Checks whether the limiter is unlimited.
    pub fn is_unlimited(&self) -> bool {
        self.unlimited
    }

    /// Returns the actual limit in KiB/s.
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Waits until the given number of bytes can be let through.
    pub async fn wait(&self, bytes: usize) {
        if bytes == 0 || self.unlimited {
            return;
        }
        let bytes = NonZeroU32::new(bytes as u32).unwrap();
        while let Err(err) = self.inner.check_n(bytes) {
            match err {
                NegativeMultiDecision::BatchNonConforming(_, until) => {
                    smol::Timer::at(until.earliest_possible()).await;
                }
                NegativeMultiDecision::InsufficientCapacity(_) => {
                    panic!("insufficient capacity in rate limiter")
                }
            }
        }
    }
}
