use anyhow::Context;
use arrayref::array_ref;
use async_trait::async_trait;
use bytes::Bytes;
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
use stdcode::StdcodeSerializeExt;

use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
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
                    let limiter = client_exit
                        .0
                        .limiter()
                        .unwrap_or_else(|| RateLimiter::unlimited(None));
                    let vpn_ipv4 = client_exit.0.get_vpn_ipv4().await.unwrap();
                    let downstream = vpn_subscribe_down(vpn_ipv4);

                    let send_loop = async {
                        let mut buff = vec![];
                        loop {
                            buff.clear();
                            let next = downstream.recv().await?;
                            buff.push(next);
                            while let Ok(next) = downstream.try_recv() {
                                buff.push(next);
                                if buff.len() >= 20 {
                                    break;
                                }
                            }
                            for next in buff.iter() {
                                limiter.wait(next.len()).await;
                            }
                            vpn_stream
                                .send_urel(stdcode::serialize(&buff)?.into())
                                .await?;
                        }
                    };
                    let recv_loop = async {
                        loop {
                            let next = vpn_stream.recv_urel().await?;
                            let next: Vec<Bytes> = stdcode::deserialize(&next)?;
                            for next in next {
                                limiter.wait(next.len()).await;
                                vpn_send_up(&ctx, vpn_ipv4, &next).await;
                            }
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
    if client_exit.0.authed().is_none() && ctx.config.official().is_some() {
        anyhow::bail!("not authed yet, cannot do anything")
    }

    // MAIN STUFF HERE
    let limiter = client_exit
        .0
        .limiter()
        .unwrap_or_else(|| RateLimiter::unlimited(None));
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
    authed: AtomicU64,
    vpn_ipv4: Option<Ipv4Addr>,
}

impl ClientExitImpl {
    /// Creates a new ClientExitImpl.
    pub fn new(ctx: Arc<RootCtx>, vpn_ipv4: Option<Ipv4Addr>) -> Self {
        Self {
            ctx,
            is_plus: AtomicBool::new(false),
            authed: AtomicU64::new(0), // FIX LATER
            vpn_ipv4,
        }
    }

    /// Gets the ratelimit
    pub fn limiter(&self) -> Option<RateLimiter> {
        Some(if self.is_plus() {
            self.ctx.get_ratelimit(self.authed()?, false)
        } else {
            self.ctx.get_ratelimit(self.authed()?, true)
        })
    }

    /// Checks whether or not the authentication has completed.
    pub fn authed(&self) -> Option<u64> {
        let out = self.authed.load(Ordering::SeqCst);
        if out > 0 {
            Some(out)
        } else {
            None
        }
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
        let h = blake3::hash(&token.stdcode());
        let token_id = u64::from_le_bytes(*array_ref![h.as_bytes(), 0, 8]);
        match fallible.await {
            Ok(val) => {
                if token.level == Level::Plus {
                    self.is_plus.store(true, Ordering::SeqCst);
                }
                self.authed.store(token_id, Ordering::SeqCst);
                val
            }
            Err(_) => {
                self.authed.store(token_id, Ordering::SeqCst);
                true
            }
        }
    }

    async fn telemetry_heartbeat(&self, _tele: ClientTelemetry) {}

    async fn get_vpn_ipv4(&self) -> Option<Ipv4Addr> {
        self.vpn_ipv4
    }
}
