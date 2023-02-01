use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use event_listener::Event;
use parking_lot::Mutex;

/// Creates a new "smart channel" with a given capacity and time bound.
pub fn smart_channel<T>(
    capacity: usize,
    time_limit: Duration,
) -> (SmartSender<T>, SmartReceiver<T>) {
    let sender = SmartSender {
        inner: Default::default(),
        count_limit: capacity,
        time_limit,
        notify: Arc::new(Event::new()),
        death: Default::default(),
    };
    let receiver = SmartReceiver {
        inner: sender.inner.clone(),
        notify: sender.notify.clone(),
        death: sender.death.clone(),
    };
    (sender, receiver)
}

pub struct SmartSender<T> {
    inner: Arc<Mutex<VecDeque<(T, Instant)>>>,
    count_limit: usize,
    time_limit: Duration,
    notify: Arc<Event>,
    death: Arc<AtomicBool>,
}

impl<T> Drop for SmartSender<T> {
    fn drop(&mut self) {
        self.death.store(true, Ordering::SeqCst);
        self.notify.notify(usize::MAX);
    }
}

impl<T> SmartSender<T> {
    /// Attempts to send into the channel. If full, silently drops.
    pub fn send_or_drop(&self, elem: T) {
        let mut inner = self.inner.lock();
        if inner.len() + 1 >= self.count_limit
            || inner
                .front()
                .map(|b| b.1.elapsed() > self.time_limit)
                .unwrap_or_default()
        {
            // HEAD drop!
            inner.pop_front();
        }
        inner.push_back((elem, Instant::now()));
        self.notify.notify_additional(1);
    }
}

pub struct SmartReceiver<T> {
    inner: Arc<Mutex<VecDeque<(T, Instant)>>>,
    notify: Arc<Event>,
    death: Arc<AtomicBool>,
}

impl<T> SmartReceiver<T> {
    /// Blocks until something arrives.
    pub async fn recv(&self) -> anyhow::Result<T> {
        loop {
            let next_event = self.notify.listen();
            {
                if self.death.load(Ordering::SeqCst) {
                    anyhow::bail!("channel closed")
                }
                let mut inner = self.inner.lock();
                if let Some(val) = inner.pop_front() {
                    return Ok(val.0);
                }
            }
            next_event.await;
        }
    }

    /// Tries to receive.
    pub fn try_recv(&self) -> anyhow::Result<T> {
        let mut inner = self.inner.lock();
        inner.pop_front().map(|s| s.0).context("channel is empty")
    }
}
