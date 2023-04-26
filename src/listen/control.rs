use crate::{asn::MY_PUBLIC_IP, stats::StatsPipe};

use super::{session_v2::handle_pipe_v2, RootCtx};

use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::Signer;

use geph4_protocol::{
    binder::protocol::BridgeDescriptor,
    bridge_exit::{BridgeExitProtocol, LegacyProtocol},
};
use moka::sync::Cache;
use native_tls::TlsAcceptor;
use rand::prelude::*;

use smol_str::SmolStr;
use sosistab2::{ObfsTlsListener, ObfsUdpListener, ObfsUdpSecret, PipeListener};
use stdcode::StdcodeSerializeExt;

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, SystemTime},
};

/// The control protocol service.
#[allow(clippy::type_complexity)]
pub struct ControlService {
    ctx: Arc<RootCtx>,

    /// Cache of udp stuff
    v2_obfsudp_listeners: Cache<SocketAddr, (SocketAddr, Arc<smol::Task<Infallible>>)>,
    /// Cache of tls stuff
    v2_obfstls_listeners: Cache<SocketAddr, (SocketAddr, Arc<smol::Task<Infallible>>)>,
}

impl ControlService {
    pub fn new(ctx: Arc<RootCtx>) -> Self {
        Self {
            ctx,

            v2_obfstls_listeners: Cache::builder()
                .time_to_idle(Duration::from_secs(120))
                .build(),
            v2_obfsudp_listeners: Cache::builder()
                .time_to_idle(Duration::from_secs(120))
                .build(),
        }
    }
}

pub fn dummy_tls_config() -> TlsAcceptor {
    let cert = rcgen::generate_simple_self_signed(vec!["helloworld.com".to_string()]).unwrap();
    let cert_pem = cert.serialize_pem().unwrap();
    let cert_key = cert.serialize_private_key_pem();
    let identity = native_tls::Identity::from_pkcs8(cert_pem.as_bytes(), cert_key.as_bytes())
        .expect("wtf cannot decode id???");
    native_tls::TlsAcceptor::new(identity).unwrap()
}

async fn forward_and_upload(
    ctx: Arc<RootCtx>,
    listener: impl PipeListener + Send + Sync + 'static,
    bd_template: BridgeDescriptor,
) -> Infallible {
    ctx.control_count.fetch_add(1, Ordering::Relaxed);
    scopeguard::defer!({
        ctx.control_count.fetch_sub(1, Ordering::Relaxed);
    });
    let bridge_pkt_key = {
        let exit_hostname = ctx.exit_hostname_dashed();
        move |bridge_group: &str| {
            format!(
                "raw_flow.{}.{}",
                exit_hostname.replace('.', "-"),
                bridge_group.replace('.', "-")
            )
        }
    };
    let flow_key = bridge_pkt_key(&bd_template.alloc_group);
    let _forwarder = {
        let ctx = ctx.clone();
        smolscale::spawn(async move {
            loop {
                let pipe = listener
                    .accept_pipe()
                    .await
                    .expect("oh no how did this happen");
                if let Some(stat_client) = ctx.stat_client.as_ref() {
                    handle_pipe_v2(
                        ctx.clone(),
                        StatsPipe::new(pipe, stat_client.clone(), flow_key.clone()),
                    );
                } else {
                    handle_pipe_v2(ctx.clone(), pipe);
                }
            }
        })
    };
    binder_upload_loop(ctx.clone(), bd_template).await
}

#[async_trait]
impl BridgeExitProtocol for ControlService {
    async fn load_factor(&self) -> f64 {
        self.ctx.load_factor.load(Ordering::Relaxed)
    }
    async fn advertise_raw_v2(
        &self,
        protocol: SmolStr,
        bridge_addr: SocketAddr,
        bridge_group: SmolStr,
    ) -> SocketAddr {
        match protocol.as_str() {
            "sosistab2-obfstls" => {
                // Placeholder, UNAUTHENTICATED rcgen-based solution
                if let Some((addr, _)) = self.v2_obfstls_listeners.get(&bridge_addr) {
                    return addr;
                };
                let cookie = *blake3::hash(
                    &(
                        self.ctx.signing_sk.secret.to_bytes(),
                        bridge_addr,
                        protocol,
                        "tls-cookie-hash-gen-lala",
                    )
                        .stdcode(),
                )
                .as_bytes();
                let mut rng = rand::rngs::StdRng::from_seed(cookie);
                let (addr, listener) = loop {
                    let addr: SocketAddr = format!("[::0]:{}", rng.gen_range(1000, 60000))
                        .parse()
                        .unwrap();
                    match ObfsTlsListener::bind(
                        addr,
                        dummy_tls_config(),
                        Bytes::copy_from_slice(&cookie),
                    )
                    .await
                    {
                        Ok(listener) => break (addr, listener),
                        Err(_err) => {
                            log::warn!("cannot bind to {}", addr);
                        }
                    }
                };
                let my_addr = SocketAddr::new((*MY_PUBLIC_IP).into(), addr.port());
                let ctx = self.ctx.clone();
                self.v2_obfstls_listeners.insert(
                    bridge_addr,
                    (
                        my_addr,
                        smolscale::spawn(forward_and_upload(
                            ctx.clone(),
                            listener,
                            BridgeDescriptor {
                                is_direct: false,
                                protocol: "sosistab2-obfstls".into(),
                                endpoint: bridge_addr,
                                sosistab_key: Bytes::copy_from_slice(&cookie),
                                exit_hostname: ctx.exit_hostname().into(),
                                alloc_group: bridge_group,
                                update_time: 0,
                                exit_signature: Bytes::new(),
                            },
                        ))
                        .into(),
                    ),
                );

                my_addr
            }
            "sosistab2-obfsudp" => {
                if let Some((addr, _)) = self.v2_obfsudp_listeners.get(&bridge_addr) {
                    return addr;
                };
                // generate a X25519 private key deterministically
                let secret_key = {
                    let mut hash = *blake3::hash(
                        &(
                            self.ctx.signing_sk.secret.to_bytes(),
                            bridge_addr,
                            protocol,
                            "x25519-hash-gen-lala-ohno",
                        )
                            .stdcode(),
                    )
                    .as_bytes();
                    // standard x25519 clamping
                    hash[0] &= 248;
                    hash[31] &= 127;
                    hash[31] |= 64;
                    ObfsUdpSecret::from_bytes(hash)
                };
                let mut rng = rand::rngs::StdRng::from_seed(secret_key.to_bytes());
                // create a listener
                let (addr, listener, _) = loop {
                    let addr: SocketAddr = format!("[::0]:{}", rng.gen_range(1000, 60000))
                        .parse()
                        .unwrap();

                    match ObfsUdpListener::bind(addr, secret_key.clone()) {
                        Ok(listener) => break (addr, listener, secret_key.to_public()),
                        Err(_err) => {
                            log::warn!("cannot bind to {}", addr);
                        }
                    }
                };
                let my_addr = SocketAddr::new((*MY_PUBLIC_IP).into(), addr.port());
                let ctx = self.ctx.clone();
                self.v2_obfsudp_listeners.insert(
                    bridge_addr,
                    (
                        my_addr,
                        smolscale::spawn(forward_and_upload(
                            ctx.clone(),
                            listener,
                            BridgeDescriptor {
                                is_direct: false,
                                protocol: "sosistab2-obfsudp".into(),
                                endpoint: bridge_addr,
                                sosistab_key: secret_key.to_public().as_bytes().to_vec().into(),
                                exit_hostname: ctx.exit_hostname().into(),
                                alloc_group: bridge_group,
                                update_time: 0,
                                exit_signature: Bytes::new(),
                            },
                        ))
                        .into(),
                    ),
                );

                my_addr
            }
            _ => {
                // return a dummy
                "0.0.0.0:12345".parse().unwrap()
            }
        }
    }

    async fn advertise_raw(
        &self,
        _protocol: LegacyProtocol,
        _bridge_addr: SocketAddr,
        _bridge_group: SmolStr,
    ) -> SocketAddr {
        // return a dummy
        "0.0.0.0:12345".parse().unwrap()
    }
}

async fn binder_upload_loop(ctx: Arc<RootCtx>, bd_template: BridgeDescriptor) -> Infallible {
    // main loop that just uploads stuff to the binder indefinitely
    loop {
        let route_unixtime = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let bridge_descriptor = {
            let mut unsigned = bd_template.clone();
            unsigned.update_time = route_unixtime;
            let signature = ctx
                .signing_sk
                .sign(&bincode::serialize(&unsigned).unwrap())
                .to_bytes()
                .to_vec()
                .into();
            unsigned.exit_signature = signature;
            unsigned
        };

        while let Err(err) = ctx
            .binder_client
            .as_ref()
            .unwrap()
            .add_bridge_route(bridge_descriptor.clone())
            .await
        {
            log::warn!("{:?}", err);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
        smol::Timer::after(Duration::from_secs(fastrand::u64(120..200))).await;
    }
}
