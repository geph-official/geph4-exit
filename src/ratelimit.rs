use std::{num::NonZeroU32, ops::Deref, sync::atomic::AtomicU64};

use async_recursion::async_recursion;
use governor::{state::NotKeyed, NegativeMultiDecision, Quota};
use once_cell::sync::Lazy;

pub static STAT_LIMITER: Lazy<
    governor::RateLimiter<
        NotKeyed,
        governor::state::InMemoryState,
        governor::clock::MonotonicClock,
    >,
> = Lazy::new(|| {
    let limit = NonZeroU32::new(10).unwrap();
    governor::RateLimiter::new(
        Quota::per_second(limit).allow_burst(NonZeroU32::new(1000).unwrap()),
        governor::state::InMemoryState::default(),
        &governor::clock::MonotonicClock::default(),
    )
});

pub static TOTAL_BW_COUNT: AtomicU64 = AtomicU64::new(0);

static GLOBAL_RATE_LIMIT: Lazy<RateLimiter> = Lazy::new(|| RateLimiter::new(80_000));

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
        let burst_size = NonZeroU32::new(l * 1024 * 10).unwrap();
        // 10-second buffer
        let inner = governor::RateLimiter::new(
            Quota::per_second(limit).allow_burst(burst_size),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        );
        inner.check_n(burst_size).expect("this should never happen");
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
    #[async_recursion]
    pub async fn wait(&self, bytes: usize) {
        if bytes == 0 || self.unlimited {
            return;
        }
        if (self as *const _) != (GLOBAL_RATE_LIMIT.deref() as *const _) {
            GLOBAL_RATE_LIMIT.wait(bytes).await;
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
