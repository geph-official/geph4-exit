use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::{asn::MY_PUBLIC_IP, config::Config, ratelimit::STAT_LIMITER, vpn};
use event_listener::Event;
use geph4_binder_transport::{BinderClient, HttpClient};

use dashmap::DashMap;
use geph4_protocol::bridge_exit::serve_bridge_exit;

use smol::{channel::Sender, fs::unix::PermissionsExt, prelude::*};

use sosistab::Session;
use sysinfo::{System, SystemExt};
use x25519_dalek::StaticSecret;

use self::control::ControlService;

mod control;
mod session;
/// the root context
pub struct RootCtx {
    pub config: Config,
    pub stat_client: Option<Arc<statsd::Client>>,
    // pub exit_hostname: String,
    binder_client: Option<Arc<dyn BinderClient>>,
    // bridge_secret: String,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,

    session_count: AtomicUsize,
    raw_session_count: AtomicUsize,
    pub conn_count: AtomicUsize,
    pub control_count: AtomicUsize,

    // free_limit: u32,
    // pub port_whitelist: bool,

    // pub google_proxy: Option<SocketAddr>,
    pub sess_replacers: DashMap<[u8; 32], Sender<Session>>,
    pub kill_event: Event,
}

impl From<Config> for RootCtx {
    fn from(cfg: Config) -> Self {
        let signing_sk = {
            match std::fs::read(cfg.secret_key()) {
                Ok(vec) => {
                    bincode::deserialize(&vec).expect("failed to deserialize my own secret key")
                }
                Err(err) => {
                    log::warn!(
                        "can't read signing_sk, so creating one and saving it! {}",
                        err
                    );
                    let new_keypair = ed25519_dalek::Keypair::generate(&mut rand::rngs::OsRng {});
                    if let Err(err) =
                        std::fs::write(cfg.secret_key(), bincode::serialize(&new_keypair).unwrap())
                    {
                        log::error!("cannot save signing_sk persistently!!! {}", err);
                    } else {
                        let mut perms = std::fs::metadata(cfg.secret_key()).unwrap().permissions();
                        perms.set_readonly(true);
                        perms.set_mode(0o600);
                        std::fs::set_permissions(cfg.secret_key(), perms).unwrap();
                    }
                    new_keypair
                }
            }
        };
        log::info!("signing_sk = {}", hex::encode(signing_sk.public));
        let sosistab_sk = x25519_dalek::StaticSecret::from(*signing_sk.secret.as_bytes());
        Self {
            config: cfg.clone(),
            stat_client: cfg.official().as_ref().map(|official| {
                Arc::new(statsd::Client::new(official.statsd_addr(), "geph4").unwrap())
            }),
            binder_client: cfg.official().as_ref().map(|official| {
                let bclient: Arc<dyn BinderClient> = Arc::new(HttpClient::new(
                    bincode::deserialize(
                        &hex::decode(official.binder_master_pk())
                            .expect("invalid hex in binder pk"),
                    )
                    .expect("invalid format of master binder pk"),
                    official.binder_http(),
                    &[],
                    None,
                ));
                bclient
            }),
            signing_sk,
            sosistab_sk,

            session_count: Default::default(),
            raw_session_count: Default::default(),
            conn_count: Default::default(),
            control_count: Default::default(),

            sess_replacers: Default::default(),
            kill_event: Event::new(),
        }
    }
}

impl RootCtx {
    pub fn exit_hostname(&self) -> String {
        self.config
            .official()
            .as_ref()
            .map(|official| official.exit_hostname().to_owned())
            .unwrap_or_default()
            .replace('.', "-")
    }

    fn new_sess(self: &Arc<Self>, sess: sosistab::Session) -> SessCtx {
        SessCtx {
            root: self.clone(),
            sess,
        }
    }

    async fn listen_udp(
        &self,
        sk: Option<StaticSecret>,
        addr: SocketAddr,
        flow_key: &str,
    ) -> std::io::Result<sosistab::Listener> {
        let stat = self.stat_client.clone();
        let stat2 = self.stat_client.clone();
        let flow_key = flow_key.to_owned();
        let fk2 = flow_key.clone();
        let long_sk = if let Some(sk) = sk {
            sk
        } else {
            self.sosistab_sk.clone()
        };
        let stat_count = Arc::new(AtomicU64::new(0));
        let sc2 = stat_count.clone();
        sosistab::Listener::listen_udp(
            addr,
            long_sk,
            move |len, _| {
                if let Some(stat) = stat.as_ref() {
                    stat_count.fetch_add(len as u64, Ordering::Relaxed);
                    if fastrand::f64() < 0.01 && STAT_LIMITER.check().is_ok() {
                        stat.count(&flow_key, stat_count.swap(0, Ordering::Relaxed) as f64)
                    }
                }
            },
            move |len, _| {
                if let Some(stat2) = stat2.as_ref() {
                    sc2.fetch_add(len as u64, Ordering::Relaxed);
                    if fastrand::f64() < 0.01 && STAT_LIMITER.check().is_ok() {
                        stat2.count(&fk2, sc2.swap(0, Ordering::Relaxed) as f64)
                    }
                }
            },
        )
        .await
    }

    async fn listen_tcp(
        &self,
        sk: Option<StaticSecret>,
        addr: SocketAddr,
        flow_key: &str,
    ) -> std::io::Result<sosistab::Listener> {
        let stat = self.stat_client.clone();
        let stat2 = self.stat_client.clone();
        let flow_key = flow_key.to_owned();
        let fk2 = flow_key.clone();
        let long_sk = if let Some(sk) = sk {
            sk
        } else {
            self.sosistab_sk.clone()
        };
        sosistab::Listener::listen_tcp(
            addr,
            long_sk,
            move |len, _| {
                if let Some(stat) = stat.as_ref() {
                    if fastrand::f32() < 0.05 {
                        stat.count(&flow_key, len as f64 * 20.0)
                    }
                }
            },
            move |len, _| {
                if let Some(stat2) = stat2.as_ref() {
                    if fastrand::f32() < 0.05 {
                        stat2.count(&fk2, len as f64 * 20.0)
                    }
                }
            },
        )
        .await
    }
}

async fn idlejitter(ctx: Arc<RootCtx>) {
    const INTERVAL: Duration = Duration::from_millis(10);
    loop {
        let start = Instant::now();
        smol::Timer::after(INTERVAL).await;
        let elapsed = start.elapsed();
        if let Some(official) = ctx.config.official() {
            if rand::random::<f32>() < 0.01 {
                let key = format!("idlejitter.{}", official.exit_hostname().replace('.', "-"));
                ctx.stat_client
                    .as_ref()
                    .as_ref()
                    .unwrap()
                    .timer(&key, elapsed.as_secs_f64() * 1000.0);
            }
        }
    }
}

async fn killconn(ctx: Arc<RootCtx>) {
    loop {
        if ctx.conn_count.load(Ordering::Relaxed) > ctx.config.conn_count_limit() {
            ctx.kill_event
                .notify_relaxed(ctx.config.conn_count_limit() / 8)
        }
        smol::Timer::after(Duration::from_secs(5)).await;
    }
}

/// per-session context
pub struct SessCtx {
    root: Arc<RootCtx>,
    sess: sosistab::Session,
}

/// the main listening loop
#[allow(clippy::too_many_arguments)]
pub async fn main_loop(ctx: Arc<RootCtx>) -> anyhow::Result<()> {
    let exit_hostname = ctx
        .config
        .official()
        .as_ref()
        .map(|official| official.exit_hostname().to_owned())
        .unwrap_or_default();
    let _idlejitter = smolscale::spawn(idlejitter(ctx.clone()));
    let _killconn = smolscale::spawn(killconn(ctx.clone()));
    let _vpn = smolscale::spawn(vpn::transparent_proxy_helper(ctx.clone()));

    // control protocol listener
    // future that governs the control protocol
    let control_prot_fut = async {
        if ctx.config.official().is_some() {
            let ctx = ctx.clone();
            let secret = blake3::hash(
                ctx.config
                    .official()
                    .as_ref()
                    .unwrap()
                    .bridge_secret()
                    .as_bytes(),
            );
            let socket = smol::net::UdpSocket::bind("0.0.0.0:28080").await?;
            serve_bridge_exit(
                socket,
                *secret.as_bytes(),
                geph4_protocol::bridge_exit::BridgeExitService(ControlService::new(ctx)),
            )
            .await?;
            Ok(())
        } else {
            smol::future::pending().await
        }
    };
    let exit_hostname2 = exit_hostname.to_string();
    let bridge_pkt_key = move |bridge_group: &str| {
        format!(
            "raw_flow.{}.{}",
            exit_hostname2.replace('.', "-"),
            bridge_group.replace('.', "-")
        )
    };
    // future that governs the "self bridge"
    let ctx1 = ctx.clone();
    let self_bridge_fut = async {
        let flow_key = bridge_pkt_key("SELF");
        let listen_addr: SocketAddr = ctx.config.sosistab_listen().parse().unwrap();
        log::info!(
            "listening on {}@{}:{}",
            hex::encode(x25519_dalek::PublicKey::from(&ctx.sosistab_sk).to_bytes()),
            if listen_addr.ip().is_unspecified() {
                IpAddr::from(*MY_PUBLIC_IP)
            } else {
                listen_addr.ip()
            },
            listen_addr.port()
        );
        let udp_listen = ctx.listen_udp(None, listen_addr, &flow_key).await.unwrap();
        let tcp_listen = ctx.listen_tcp(None, listen_addr, &flow_key).await.unwrap();
        log::debug!("sosis_listener initialized");

        loop {
            let sess = udp_listen
                .accept_session()
                .race(tcp_listen.accept_session())
                .await
                .expect("can't accept from sosistab");
            let ctx1 = ctx1.clone();
            smolscale::spawn(session::handle_session(ctx1.new_sess(sess))).detach();
        }
    };
    // future that uploads gauge statistics
    let gauge_fut = async {
        let key = format!("session_count.{}", exit_hostname.replace('.', "-"));
        let rskey = format!("raw_session_count.{}", exit_hostname.replace('.', "-"));
        let memkey = format!("bytes_allocated.{}", exit_hostname.replace('.', "-"));
        let connkey = format!("conn_count.{}", exit_hostname.replace('.', "-"));
        let threadkey = format!("thread_key.{}", exit_hostname.replace('.', "-"));
        let ctrlkey = format!("control_count.{}", exit_hostname.replace('.', "-"));
        let taskkey = format!("task_count.{}", exit_hostname.replace('.', "-"));
        let hijackkey = format!("hijackers.{}", exit_hostname.replace('.', "-"));
        let mut sys = System::new_all();

        loop {
            sys.refresh_all();
            if let Some(stat_client) = ctx.stat_client.as_ref() {
                let session_count = ctx.session_count.load(std::sync::atomic::Ordering::Relaxed);
                stat_client.gauge(&key, session_count as f64);
                let raw_session_count = ctx
                    .raw_session_count
                    .load(std::sync::atomic::Ordering::Relaxed);
                stat_client.gauge(&rskey, raw_session_count as f64);
                let memory_usage = sys.total_memory() - sys.available_memory();
                stat_client.gauge(&memkey, memory_usage as f64);
                let conn_count = ctx.conn_count.load(std::sync::atomic::Ordering::Relaxed);
                stat_client.gauge(&connkey, conn_count as f64);
                let control_count = ctx.control_count.load(std::sync::atomic::Ordering::Relaxed);
                stat_client.gauge(&ctrlkey, control_count as f64);
                let task_count = smolscale::active_task_count();
                let thread_count = smolscale::running_threads();
                stat_client.gauge(&taskkey, task_count as f64);
                stat_client.gauge(&threadkey, thread_count as f64);
                stat_client.gauge(&hijackkey, ctx.sess_replacers.len() as f64);
            }
            smol::Timer::after(Duration::from_secs(10)).await;
        }
    };
    // race
    smol::future::race(control_prot_fut, self_bridge_fut)
        .or(gauge_fut)
        .await
}
