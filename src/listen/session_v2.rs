use async_trait::async_trait;
use futures_util::{AsyncReadExt, AsyncWriteExt, TryFutureExt};
use geph4_protocol::{
    binder::protocol::{BlindToken, Level},
    client_exit::{ClientExitProtocol, ClientExitService, ClientTelemetry, CLIENT_EXIT_PSEUDOHOST},
};
use moka::sync::Cache;
use nanorpc::{JrpcRequest, RpcService};
use once_cell::sync::Lazy;
use rand::Rng;
use smol::{
    io::{AsyncBufReadExt, BufReader},
    stream::StreamExt,
    Task,
};

use sosistab2::MuxStream;

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{connect::proxy_loop, ratelimit::RateLimiter};

use super::RootCtx;

type TableEntry = (Arc<sosistab2::Multiplex>, Arc<Task<anyhow::Result<()>>>);

/// Handles a sosistab2 pipe, redirecting it to the appropriate multiplex.
pub fn handle_pipe_v2(ctx: Arc<RootCtx>, pipe: impl sosistab2::Pipe) {
    static BIG_MULTIPLEX_TABLE: Lazy<Cache<blake3::Hash, TableEntry>> = Lazy::new(|| {
        Cache::builder()
            .max_capacity(100_000)
            .time_to_idle(Duration::from_secs(3600))
            .build()
    });
    let key = blake3::hash(pipe.peer_metadata().as_bytes());
    log::debug!("sesh: {}", key);
    let (mplex, _) = BIG_MULTIPLEX_TABLE.get_with(key, || {
        log::debug!("sesh MISS: {}", key);
        // TODO actually put this SK somewhere
        let mplex = Arc::new(sosistab2::Multiplex::new(ctx.sosistab2_sk.clone(), None));
        let task = smolscale::spawn(handle_session_v2(ctx.clone(), mplex.clone()));
        (mplex, task.into())
    });
    mplex.add_pipe(pipe);
}

/// Handles a sosistab2 multiplex. We do not try to timeout etc here. The Big Multiplex Table handles this.
async fn handle_session_v2(
    ctx: Arc<RootCtx>,
    mux: Arc<sosistab2::Multiplex>,
) -> anyhow::Result<()> {
    let client_exit = Arc::new(ClientExitService(ClientExitImpl::new(ctx.clone())));
    // let reaper = TaskReaper::new();
    loop {
        let conn = mux.accept_conn().await?;

        smolscale::spawn(
            handle_conn(
                ctx.clone(),
                client_exit.clone(),
                conn,
                rand::thread_rng().gen(),
            )
            .map_err(|e| log::debug!("connection handler died with {:?}", e)),
        )
        .detach();
    }
}

async fn handle_conn(
    ctx: Arc<RootCtx>,
    client_exit: Arc<ClientExitService<ClientExitImpl>>,
    mut stream: MuxStream,
    sess_random: u64,
) -> anyhow::Result<()> {
    let hostname = stream.additional_info();
    log::debug!("req for {hostname}");
    if hostname == CLIENT_EXIT_PSEUDOHOST {
        // run the loop
        let up_read = BufReader::new(stream.clone()).take(1_000_000);
        let mut lines = up_read.lines();

        while let Some(line) = lines.next().await {
            let line: JrpcRequest = serde_json::from_str(&line?)?;
            let resp = client_exit.respond_raw(line).await;
            stream.write_all(&serde_json::to_vec(&resp)?).await?;
            stream.write_all(b"\n").await?;
        }

        return Ok(());
    }
    // check auth
    if !client_exit.0.authed() {
        anyhow::bail!("not authed yet, cannot do anything")
    }

    // MAIN STUFF HERE
    let limiter = if client_exit.0.is_plus() {
        RateLimiter::unlimited()
    } else {
        RateLimiter::new(
            ctx.config
                .official()
                .as_ref()
                .and_then(|off| *off.free_limit())
                .unwrap_or(125),
        )
    };
    proxy_loop(
        ctx,
        limiter.into(),
        stream.clone(),
        sess_random,
        hostname.into(),
        true,
    )
    .await?;
    Ok(())
}

/// Encapsulates the client-exit protocol state.
struct ClientExitImpl {
    ctx: Arc<RootCtx>,
    is_plus: AtomicBool,
    authed: AtomicBool,
}

impl ClientExitImpl {
    /// Creates a new ClientExitImpl.
    pub fn new(ctx: Arc<RootCtx>) -> Self {
        Self {
            ctx,
            is_plus: AtomicBool::new(false),
            authed: AtomicBool::new(true), // FIX LATER
        }
    }

    /// Checks whether or not the authentication has completed.
    pub fn authed(&self) -> bool {
        self.authed.load(Ordering::SeqCst)
    }

    /// Checks whether or not this is Plus.
    pub fn is_plus(&self) -> bool {
        self.is_plus.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ClientExitProtocol for ClientExitImpl {
    async fn validate(&self, token: BlindToken) -> bool {
        // fail-open
        let fallible = async {
            if let Some(client) = self.ctx.binder_client.as_ref() {
                anyhow::Ok(client.validate(token.clone()).await?)
            } else {
                anyhow::Ok(true)
            }
        };
        match fallible.await {
            Ok(val) => {
                if token.level == Level::Plus {
                    self.is_plus.store(true, Ordering::SeqCst);
                }
                self.authed.store(val, Ordering::SeqCst);
                val
            }
            Err(_) => {
                self.authed.store(true, Ordering::SeqCst);
                true
            }
        }
    }

    async fn telemetry_heartbeat(&self, _tele: ClientTelemetry) {}
}
