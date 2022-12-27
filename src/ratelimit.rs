use async_recursion::async_recursion;
use atomic_float::AtomicF64;
use governor::{state::NotKeyed, NegativeMultiDecision, Quota};
use once_cell::sync::Lazy;
use std::{
    num::NonZeroU32,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use rand::Rng;

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
    limit: u32,

    parent: Option<Box<RateLimiter>>,
    priority: Arc<AtomicU64>,
    divider: Arc<AtomicF64>,
    start: Instant,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given speed limit, in KB/s
    pub fn new(limit_kb: u32, burst_kb: u32, parent: Option<RateLimiter>) -> Self {
        let limit = NonZeroU32::new((limit_kb + 1) * 1024).unwrap();
        let burst_size = NonZeroU32::new(burst_kb * 1024).unwrap();
        let inner = governor::RateLimiter::new(
            Quota::per_second(limit).allow_burst(burst_size),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        );
        inner.check_n(burst_size).expect("this should never happen");
        Self {
            inner: Arc::new(inner),
            unlimited: false,
            limit: limit_kb,
            parent: parent.map(Box::new),
            priority: AtomicU64::new(0).into(),
            start: Instant::now(),
            divider: Arc::new(AtomicF64::new(1.0)),
        }
    }

    /// Creates a new unlimited ratelimit.
    pub fn unlimited(parent: Option<RateLimiter>) -> Self {
        let inner = Arc::new(governor::RateLimiter::new(
            Quota::per_second(NonZeroU32::new(128 * 1024).unwrap()),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        ));
        Self {
            inner,
            unlimited: true,
            limit: u32::MAX,
            parent: parent.map(Box::new),
            priority: AtomicU64::new(0).into(),
            start: Instant::now(),
            divider: Arc::new(AtomicF64::new(1.0)),
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

    /// Sets the divider. The actual speed limit is reduced by this factor.
    pub fn set_divider(&self, divider: f64) {
        self.divider.store(divider, Ordering::Relaxed);
    }

    /// Waits until the given number of bytes can be let through.
    pub async fn wait(&self, bytes: usize) {
        let priority_raw = self.priority.load(Ordering::Relaxed) as f64;
        let priority = (priority_raw / self.start.elapsed().as_secs_f64()).sqrt() as u32;

        self.wait_priority(bytes, if self.unlimited { 0 } else { priority })
            .await;
    }

    #[async_recursion]
    async fn wait_priority(&self, obytes: usize, priority: u32) {
        let divider = self.divider.load(Ordering::Relaxed);

        let obytes = (obytes as f64 * divider) as usize;
        if let Some(v) = &self.parent {
            v.wait_priority(obytes, priority).await;
        }
        if obytes == 0 || self.unlimited {
            return;
        }
        let bytes = NonZeroU32::new(obytes as u32).unwrap();
        let mut init_sleep = priority as f64 / 10.0;
        while let Err(err) = self.inner.check_n(bytes) {
            match err {
                NegativeMultiDecision::BatchNonConforming(_, until) => {
                    let delay = rand::thread_rng().gen_range(init_sleep, init_sleep * 2.0 + 1.0);
                    smol::Timer::at(
                        until.earliest_possible() + Duration::from_secs_f64(delay / 1000.0),
                    )
                    .await;
                    init_sleep *= 2.0;
                }
                NegativeMultiDecision::InsufficientCapacity(_) => {
                    panic!("insufficient capacity in rate limiter")
                }
            }
        }
        self.priority
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| {
                Some(x.saturating_add(obytes as u64))
            })
            .unwrap();
    }
}
