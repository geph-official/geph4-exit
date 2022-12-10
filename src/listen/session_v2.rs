use anyhow::Context;
use async_trait::async_trait;
use dashmap::DashMap;
use futures_util::{AsyncReadExt, AsyncWriteExt, TryFutureExt};
use geph4_protocol::{
    binder::protocol::{BlindToken, Level},
    client_exit::{ClientExitProtocol, ClientExitService, ClientTelemetry, CLIENT_EXIT_PSEUDOHOST},
};

use nanorpc::{JrpcRequest, RpcService};
use once_cell::sync::Lazy;
use rand::Rng;
use smol::{
    future::FutureExt,
    io::{AsyncBufReadExt, BufReader},
    stream::StreamExt,
    Task,
};

use smol_timeout::TimeoutExt;
use smolscale::reaper::TaskReaper;
use sosistab2::MuxStream;

use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
    time::Duration,
};

use crate::{
    connect::proxy_loop,
    ratelimit::RateLimiter,
    vpn::{vpn_send_up, vpn_subscribe_down, IpAddrAssigner},
};

use super::RootCtx;

type TableEntry = (Weak<sosistab2::Multiplex>, Arc<Task<anyhow::Result<()>>>);

/// Handles a sosistab2 pipe, redirecting it to the appropriate multiplex.
pub fn handle_pipe_v2(ctx: Arc<RootCtx>, pipe: impl sosistab2::Pipe) {
    static BIG_MULTIPLEX_TABLE: Lazy<DashMap<blake3::Hash, TableEntry>> =
        Lazy::new(Default::default);
    let key = blake3::hash(pipe.peer_metadata().as_bytes());
    log::debug!("sesh: {}", key);
    let mplex = BIG_MULTIPLEX_TABLE.entry(key).or_insert_with(move || {
        log::debug!("sesh MISS: {}", key);
        // TODO actually put this SK somewhere
        let mplex = Arc::new(sosistab2::Multiplex::new(ctx.sosistab2_sk.clone(), None));
        mplex.add_drop_friend(scopeguard::guard((), move |_| {
            BIG_MULTIPLEX_TABLE.remove(&key);
        }));
        let task = smolscale::spawn(handle_session_v2(ctx, mplex.clone()));
        (Arc::downgrade(&mplex), task.into())
    });
    if let Some(mplex) = mplex.value().0.upgrade() {
        mplex.add_pipe(pipe);
    }
}

/// Handles a sosistab2 multiplex. We do not try to timeout etc here. The Big Multiplex Table handles this.
async fn handle_session_v2(
    ctx: Arc<RootCtx>,
    mux: Arc<sosistab2::Multiplex>,
) -> anyhow::Result<()> {
    let vpn_ipv4 = if ctx.config.nat_external_iface().is_some() {
        Some(IpAddrAssigner::global().assign())
    } else {
        None
    };
    let client_exit = Arc::new(ClientExitService(ClientExitImpl::new(
        ctx.clone(),
        vpn_ipv4.map(|v| v.addr()),
    )));
    let reaper = TaskReaper::new();
    loop {
        let conn = mux
            .accept_conn()
            .timeout(Duration::from_secs(3600))
            .await
            .context("timeout")??;

        reaper.attach(smolscale::spawn(
            handle_conn(
                ctx.clone(),
                client_exit.clone(),
                conn,
                rand::thread_rng().gen(),
            )
            .unwrap_or_else(|e| log::debug!("connection handler died with {:?}", e)),
        ));
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
        // also run the VPN!
        let vpn_stream = stream.clone();
        let start_vpn = ctx.config.nat_external_iface().is_some();
        let _vpn_task = {
            let client_exit = client_exit.clone();
            let ctx = ctx.clone();
            smolscale::spawn::<anyhow::Result<()>>(async move {
                vpn_stream.recv_urel().await?;
                if start_vpn {
                    let vpn_ipv4 = client_exit.0.get_vpn_ipv4().await.unwrap();
                    let downstream = vpn_subscribe_down(vpn_ipv4);

                    let send_loop = async {
                        loop {
                            let next = downstream.recv().await?;
                            vpn_stream.send_urel(next).await?;
                        }
                    };
                    let recv_loop = async {
                        loop {
                            let next = vpn_stream.recv_urel().await?;
                            vpn_send_up(&ctx, vpn_ipv4, &next).await;
                        }
                    };
                    send_loop.race(recv_loop).await
                } else {
                    Ok(())
                }
            })
        };
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
    vpn_ipv4: Option<Ipv4Addr>,
}

impl ClientExitImpl {
    /// Creates a new ClientExitImpl.
    pub fn new(ctx: Arc<RootCtx>, vpn_ipv4: Option<Ipv4Addr>) -> Self {
        Self {
            ctx,
            is_plus: AtomicBool::new(false),
            authed: AtomicBool::new(true), // FIX LATER
            vpn_ipv4,
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

    async fn get_vpn_ipv4(&self) -> Option<Ipv4Addr> {
        self.vpn_ipv4
    }
}
