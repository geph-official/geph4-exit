use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use sosistab2::{Pipe, PipeStats};

pub struct StatsPipe<P: Pipe> {
    inner: P,
    statsd_client: Arc<statsd::Client>,
    flow_key: String,
}

impl<P: Pipe> StatsPipe<P> {
    pub fn new(pipe: P, statsd_client: Arc<statsd::Client>, flow_key: String) -> Self {
        Self {
            inner: pipe,
            statsd_client,
            flow_key,
        }
    }
}

#[async_trait]
impl<P: Pipe> Pipe for StatsPipe<P> {
    async fn send(&self, to_send: Bytes) {
        if fastrand::f64() < to_send.len() as f64 / 1_000_000.0 {
            self.statsd_client.count(&self.flow_key, 1_000_000.0);
        }
        self.inner.send(to_send).await;
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        let recved = self.inner.recv().await?;
        if fastrand::f64() < recved.len() as f64 / 1_000_000.0 {
            self.statsd_client.count(&self.flow_key, 1_000_000.0);
        }
        Ok(recved)
    }

    fn get_stats(&self) -> PipeStats {
        self.inner.get_stats()
    }

    fn protocol(&self) -> &str {
        self.inner.protocol()
    }

    fn peer_metadata(&self) -> &str {
        self.inner.peer_metadata()
    }

    fn peer_addr(&self) -> String {
        self.inner.peer_addr()
    }
}
