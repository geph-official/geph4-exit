use crate::asn::MY_PUBLIC_IP;

use super::{session, RootCtx};
use anyhow::Context;
use async_trait::async_trait;
use ed25519_dalek::Signer;
use geph4_binder_transport::BinderRequestData;
use geph4_protocol::bridge_exit::{BridgeExitProtocol, RawProtocol};
use moka::sync::Cache;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use smol::prelude::*;
use smol_str::SmolStr;

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// The control protocol service.
#[allow(clippy::type_complexity)]
pub struct ControlService {
    ctx: Arc<RootCtx>,

    /// A cache mapping udp/tcp bridge endpoints to background tasks resources on their behalf.
    ///
    /// This has a very short time-to-idle to clear out outdated bridges quickly.
    bridge_to_manager: Cache<(RawProtocol, SocketAddr), (SocketAddr, Arc<smol::Task<Infallible>>)>,
}

impl ControlService {
    pub fn new(ctx: Arc<RootCtx>) -> Self {
        Self {
            ctx,
            bridge_to_manager: Cache::builder()
                .time_to_idle(Duration::from_secs(120))
                .build(),
        }
    }
}

#[async_trait]
impl BridgeExitProtocol for ControlService {
    async fn advertise_raw(
        &self,
        protocol: RawProtocol,
        bridge_addr: SocketAddr,
        bridge_group: SmolStr,
    ) -> SocketAddr {
        let bridge_pkt_key = {
            let exit_hostname = self.ctx.exit_hostname();
            move |bridge_group: &str| {
                format!(
                    "raw_flow.{}.{}",
                    exit_hostname.replace('.', "-"),
                    bridge_group.replace('.', "-")
                )
            }
        };

        if let Some((exit_addr, _)) = self.bridge_to_manager.get(&(protocol, bridge_addr)) {
            log::debug!("b2e hit {bridge_addr} => {exit_addr}");
            exit_addr
        } else {
            log::debug!("b2e MISS {bridge_addr}");
            // we DETERMINISTICALLY create a sosistab secret in order to not invalidate all routes upon restart
            let mut rng = ChaCha20Rng::from_seed(
                *blake3::keyed_hash(
                    blake3::hash(&self.ctx.signing_sk.to_bytes()).as_bytes(),
                    bridge_addr.ip().to_string().as_bytes(),
                )
                .as_bytes(),
            );
            let sosis_secret = x25519_dalek::StaticSecret::new(&mut rng);
            let flow_key = bridge_pkt_key(&bridge_group);
            let mut to_repeat = || {
                let a: SocketAddr = format!("[::0]:{}", rng.gen_range(1000, 60000))
                    .parse()
                    .unwrap();
                let ctx = self.ctx.clone();
                let sosis_secret = sosis_secret.clone();
                let flow_key = flow_key.clone();
                async move {
                    let sosis_listener_tcp = ctx
                        .listen_tcp(Some(sosis_secret.clone()), a, &flow_key)
                        .await?;
                    let sosis_listener_udp = ctx
                        .listen_udp(
                            Some(sosis_secret.clone()),
                            sosis_listener_tcp.local_addr(),
                            &flow_key,
                        )
                        .await?;

                    Ok::<_, anyhow::Error>((sosis_listener_tcp, sosis_listener_udp))
                }
            };
            let (sosis_listener_tcp, sosis_listener_udp) = loop {
                match to_repeat().await {
                    Err(err) => log::warn!("{:?}", err),
                    Ok(val) => break val,
                }
            };
            let my_port = sosis_listener_tcp.local_addr().port();
            // make the maintenance task
            let sosistab_pk = x25519_dalek::PublicKey::from(&sosis_secret);
            let ctx = self.ctx.clone();
            let maintain_task = Arc::new(smolscale::spawn(async move {
                ctx.control_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _guard = scopeguard::guard((), |_| {
                    ctx.control_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });

                let ctx2 = ctx.clone();
                // task that actually handles all the sessions etc
                let _route_task: smol::Task<anyhow::Result<()>> = smolscale::spawn(async move {
                    loop {
                        let sess = sosis_listener_udp
                            .accept_session()
                            .race(sosis_listener_tcp.accept_session())
                            .await
                            .ok_or_else(|| anyhow::anyhow!("could not accept sosis session"))?;
                        let ctx = ctx2.clone();
                        smolscale::spawn(session::handle_session(ctx.new_sess(sess))).detach();
                    }
                });
                // main loop that just uploads stuff to the binder indefinitely
                loop {
                    let route_unixtime = SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let to_sign = bincode::serialize(&(
                        sosistab_pk,
                        bridge_addr,
                        bridge_group.clone(),
                        route_unixtime,
                    ))
                    .unwrap();
                    let exit_signature = ctx.signing_sk.sign(&to_sign);
                    while let Err(err) = ctx
                        .binder_client
                        .as_ref()
                        .unwrap()
                        .request(BinderRequestData::AddBridgeRoute {
                            sosistab_pubkey: sosistab_pk,
                            bridge_address: bridge_addr,
                            bridge_group: bridge_group.clone().into(),
                            exit_hostname: ctx
                                .config
                                .official()
                                .as_ref()
                                .unwrap()
                                .exit_hostname()
                                .to_string(),
                            route_unixtime,
                            exit_signature,
                        })
                        .await
                        .context("failed to go to binder")
                    {
                        log::warn!("{:?}", err);
                        smol::Timer::after(Duration::from_secs(1)).await;
                    }
                    smol::Timer::after(Duration::from_secs(fastrand::u64(60..120))).await;
                }
            }));
            // Right now, all we do is TCP and UDP, somewhat unfortunately, due to the old binder schema.
            let my_addr = SocketAddr::new((*MY_PUBLIC_IP).into(), my_port);
            log::debug!("b2e RESOLVE {bridge_addr} => my_addr");
            self.bridge_to_manager.insert(
                (RawProtocol::Tcp, bridge_addr),
                (my_addr, maintain_task.clone()),
            );
            self.bridge_to_manager
                .insert((RawProtocol::Udp, bridge_addr), (my_addr, maintain_task));
            my_addr
        }
    }
}
