use std::time::{Duration, Instant};

use parking_lot::Mutex;
use priority_queue::PriorityQueue;

pub struct AmnesiacCounter {
    ttl: Duration,
    id_map: Mutex<PriorityQueue<u64, Instant>>,
}

impl AmnesiacCounter {
    /// Creates a new amnesiac counter, with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            id_map: Default::default(),
        }
    }

    /// Inserts a new id.
    pub fn insert(&self, id: u64) {
        self.id_map.lock().push(id, Instant::now());
    }

    /// Returns the count.
    pub fn count(&self) -> usize {
        let mut map = self.id_map.lock();
        while map
            .peek()
            .map(|p| p.1.elapsed() > self.ttl)
            .unwrap_or_default()
        {
            map.pop();
        }
        map.len()
    }
}
