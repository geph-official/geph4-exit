use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};

use crate::{
    amnesiac_counter::AmnesiacCounter,
    asn::MY_PUBLIC_IP,
    config::Config,
    listen::control::dummy_tls_config,
    ratelimit::{RateLimiter, BW_MULTIPLIER},
    stats::StatsPipe,
    vpn,
};
use atomic_float::AtomicF64;
use bytes::Bytes;
use ed25519_dalek::{ed25519::signature::Signature, Signer};
use event_listener::Event;

use geph4_protocol::{
    binder::{
        client::E2eeHttpTransport,
        protocol::{BinderClient, BridgeDescriptor},
    },
    bridge_exit::serve_bridge_exit,
};

use moka::sync::Cache;
use smol::{fs::unix::PermissionsExt, prelude::*, Task};

use sosistab2::{MuxSecret, ObfsTlsListener, ObfsUdpListener, ObfsUdpSecret, PipeListener};
use sysinfo::{CpuExt, System, SystemExt};

use self::{control::ControlService, session_v2::handle_pipe_v2};

mod control;

mod session_v2;
/// the root context
pub struct RootCtx {
    pub config: Config,
    pub stat_client: Option<Arc<statsd::Client>>,
    // pub exit_hostname: String,
    binder_client: Option<Arc<BinderClient>>,
    // bridge_secret: String,
    signing_sk: ed25519_dalek::Keypair,

    pub sosistab2_sk: MuxSecret,

    session_counter: AmnesiacCounter,
    pub conn_count: AtomicUsize,
    pub control_count: AtomicUsize,

    pub kill_event: Event,

    pub load_factor: Arc<AtomicF64>,

    mass_ratelimits: Cache<u64, RateLimiter>,

    _task: Task<()>,
}

impl From<Config> for RootCtx {
    fn from(cfg: Config) -> Self {
        let sosistab2_sk = {
            match std::fs::read(cfg.secret_sosistab2_key()) {
                Ok(vec) => {
                    bincode::deserialize(&vec).expect("failed to deserialize my own secret key")
                }
                Err(err) => {
                    log::warn!(
                        "can't read signing_sk, so creating one and saving it! {}",
                        err
                    );
                    let new_keypair = MuxSecret::generate();
                    if let Err(err) = std::fs::write(
                        cfg.secret_sosistab2_key(),
                        bincode::serialize(&new_keypair).unwrap(),
                    ) {
                        log::error!("cannot save signing_sk persistently!!! {}", err);
                    } else {
                        let mut perms = std::fs::metadata(cfg.secret_sosistab2_key())
                            .unwrap()
                            .permissions();
                        perms.set_readonly(true);
                        perms.set_mode(0o600);
                        std::fs::set_permissions(cfg.secret_sosistab2_key(), perms).unwrap();
                    }
                    new_keypair
                }
            }
        };
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

        let load_factor = Arc::new(AtomicF64::new(0.0));
        Self {
            config: cfg.clone(),
            stat_client: cfg.official().as_ref().map(|official| {
                Arc::new(statsd::Client::new(official.statsd_addr(), "geph4").unwrap())
            }),
            binder_client: cfg.official().as_ref().map(|official| {
                let bclient: Arc<BinderClient> =
                    Arc::new(BinderClient::from(E2eeHttpTransport::new(
                        bincode::deserialize(
                            &hex::decode(official.binder_master_pk())
                                .expect("invalid hex in binder pk"),
                        )
                        .expect("invalid format of master binder pk"),
                        official.binder_http().clone(),
                        vec![],
                    )));
                bclient
            }),
            signing_sk,

            sosistab2_sk,

            load_factor: load_factor.clone(),

            session_counter: AmnesiacCounter::new(Duration::from_secs(300)),
            conn_count: Default::default(),
            control_count: Default::default(),

            kill_event: Event::new(),

            mass_ratelimits: Cache::builder()
                .time_to_idle(Duration::from_secs(86400))
                .build(),

            _task: smolscale::spawn(set_ratelimit_loop(
                load_factor,
                cfg.nat_external_iface()
                    .clone()
                    .unwrap_or_else(|| String::from("lo")),
                *cfg.all_limit(),
            )),
        }
    }
}

async fn set_ratelimit_loop(load_factor: Arc<AtomicF64>, iface_name: String, all_limit: u32) {
    let mut sys = System::new_all();
    let mut i = 0.0;
    let target_usage = 0.95f32;
    let mut divider;
    let mut timer = smol::Timer::interval(Duration::from_secs(1));
    let mut last_bw_used = 0u128;
    loop {
        timer.next().await;
        sys.refresh_all();
        let cpus = sys.cpus();
        let cpu_usage = cpus.iter().map(|c| c.cpu_usage() / 100.0).sum::<f32>() / cpus.len() as f32;
        let bw_used: u128 = String::from_utf8_lossy(
            &std::fs::read(format!("/sys/class/net/{iface_name}/statistics/tx_bytes")).unwrap(),
        )
        .trim()
        .parse()
        .unwrap();
        let bw_delta = bw_used.saturating_sub(last_bw_used);
        last_bw_used = bw_used;
        let bw_usage = (bw_delta as f64 / 1000.0 / all_limit as f64) as f32;
        let total_usage = bw_usage.max(cpu_usage);
        let multiplier = if total_usage < target_usage * 0.8 {
            i = 0.0;
            BW_MULTIPLIER.swap(1.0, Ordering::Relaxed)
        } else {
            log::info!("CPU PID usage: {:.2}%", cpu_usage * 100.0);
            log::info!("B/W PID usage: {:.2}%", bw_usage * 100.0);
            let p = total_usage - target_usage;
            i += p;
            i = i.clamp(-20.0, 20.0);
            divider = 1.0 + (1.0 * p + 0.4 * i).min(100.0).max(0.0);
            log::info!("PID divider {divider}, p {p}, i {i}");
            BW_MULTIPLIER.swap(divider as f64, Ordering::Relaxed)
        };
        load_factor.store(total_usage as f64 * multiplier, Ordering::Relaxed);
    }
}

impl RootCtx {
    pub fn session_keepalive(&self, id: u64) {
        self.session_counter.insert(id);
    }

    pub fn incr_throughput(&self, delta: usize) {
        if fastrand::f64() < delta as f64 / 1_000_000.0 {
            if let Some(client) = self.stat_client.as_ref() {
                let stat_key = format!("exit_usage.{}", self.exit_hostname_dashed());
                client.count(&stat_key, 1_000_000.0);
            }
        }
    }

    pub fn exit_hostname_dashed(&self) -> String {
        self.config
            .official()
            .as_ref()
            .map(|official| official.exit_hostname().to_owned())
            .unwrap_or_default()
            .replace('.', "-")
    }

    pub fn exit_hostname(&self) -> String {
        self.config
            .official()
            .as_ref()
            .map(|official| official.exit_hostname().to_owned())
            .unwrap_or_default()
    }

    pub fn get_ratelimit(&self, key: u64, free: bool) -> RateLimiter {
        if free {
            self.mass_ratelimits.get_with(key, || {
                RateLimiter::new(
                    self.config
                        .official()
                        .as_ref()
                        .and_then(|s| *s.free_limit())
                        .unwrap_or_default(),
                    1024,
                )
            })
        } else {
            self.mass_ratelimits
                .get_with(key.rotate_left(3), || RateLimiter::new(1903, 5_000_000))
        }
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

/// the main listening loop
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
            let socket = smol::net::UdpSocket::bind("0.0.0.0:28080").await.unwrap();
            log::info!("starting bridge exit listener");
            serve_bridge_exit(
                socket,
                *secret.as_bytes(),
                geph4_protocol::bridge_exit::BridgeExitService(ControlService::new(ctx)),
            )
            .await?;
            Ok(())
        } else {
            log::info!("NOT starting bridge exit listener");
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

    // future that uploads gauge statistics
    let gauge_fut = async {
        let key = format!("session_count.{}", exit_hostname.replace('.', "-"));
        let rskey = format!("raw_session_count.{}", exit_hostname.replace('.', "-"));
        let memkey = format!("bytes_allocated.{}", exit_hostname.replace('.', "-"));
        let connkey = format!("conn_count.{}", exit_hostname.replace('.', "-"));
        let threadkey = format!("thread_key.{}", exit_hostname.replace('.', "-"));
        let ctrlkey = format!("control_count.{}", exit_hostname.replace('.', "-"));
        let taskkey = format!("task_count.{}", exit_hostname.replace('.', "-"));
        let _hijackkey = format!("hijackers.{}", exit_hostname.replace('.', "-"));
        let cpukey = format!("cpu_usage.{}", exit_hostname.replace('.', "-"));
        let loadkey = format!("load_factor.{}", exit_hostname.replace('.', "-"));
        let mut sys = System::new_all();

        loop {
            sys.refresh_all();

            if let Some(stat_client) = ctx.stat_client.as_ref() {
                let cpus = sys.cpus();
                let usage = cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32;

                let session_count = ctx.session_counter.count();
                stat_client.gauge(&key, session_count as f64);

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

                stat_client.gauge(&cpukey, usage as f64);
                stat_client.gauge(&loadkey, BW_MULTIPLIER.load(Ordering::Relaxed));
            }
            smol::Timer::after(Duration::from_secs(10)).await;
        }
    };

    let pipe_listen_fut = {
        let ctx = ctx.clone();
        let flow_key = bridge_pkt_key("SELF");
        smolscale::spawn(async move {
            // TODO this key reuse is *probably* fine security-wise, but we might wanna switch this to something else
            // This hack allows the client to deterministically get the correct ObfsUdpPublic, which is important for selfhosted instances having constant keys.
            let secret = ObfsUdpSecret::from_bytes(ctx.sosistab2_sk.to_bytes());
            let listen_addr = ctx
                .config
                .sosistab2_listen()
                .parse()
                .expect("cannot parse sosistab2 listening address");

            let udp_listener = ObfsUdpListener::bind(listen_addr, secret.clone()).unwrap();
            let tls_cookie = Bytes::copy_from_slice(secret.to_public().as_bytes());
            let tls_listener =
                ObfsTlsListener::bind(listen_addr, dummy_tls_config(), tls_cookie.clone())
                    .await
                    .unwrap();
            // Upload a "self-bridge". sosistab2 bridges have the key field be the bincode-encoded pair of bridge key and e2e key
            let mut _task = None;
            if let Some(client) = ctx.binder_client.clone() {
                let ctx = ctx.clone();
                _task = Some(smolscale::spawn(async move {
                    loop {
                        let fallible = async {
                            let mut unsigned_udp = BridgeDescriptor {
                                is_direct: true,
                                protocol: "sosistab2-obfsudp".into(),
                                endpoint: SocketAddr::new(
                                    (*MY_PUBLIC_IP).into(),
                                    listen_addr.port(),
                                ),
                                cookie: secret.to_public().as_bytes().to_vec().into(),
                                exit_hostname: ctx
                                    .config
                                    .official()
                                    .as_ref()
                                    .unwrap()
                                    .exit_hostname()
                                    .into(),
                                alloc_group: "direct".into(),
                                update_time: SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                exit_signature: Bytes::new(),
                            };
                            let sig = ctx
                                .signing_sk
                                .sign(&bincode::serialize(&unsigned_udp).unwrap());
                            unsigned_udp.exit_signature = sig.as_bytes().to_vec().into();
                            client.add_bridge_route(unsigned_udp).await??;

                            let mut unsigned_tcp = BridgeDescriptor {
                                is_direct: true,
                                protocol: "sosistab2-obfstls".into(),
                                endpoint: SocketAddr::new(
                                    (*MY_PUBLIC_IP).into(),
                                    listen_addr.port(),
                                ),
                                cookie: tls_cookie.clone(),
                                exit_hostname: ctx.exit_hostname().into(),
                                alloc_group: "direct".into(),
                                update_time: SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                exit_signature: Bytes::new(),
                            };
                            let sig = ctx
                                .signing_sk
                                .sign(&bincode::serialize(&unsigned_tcp).unwrap());
                            unsigned_tcp.exit_signature = sig.as_bytes().to_vec().into();
                            client.add_bridge_route(unsigned_tcp).await??;
                            anyhow::Ok(())
                        };
                        if let Err(err) = fallible.await {
                            log::warn!("failed to upload direct route: {:?}", err);
                        }
                        smol::Timer::after(Duration::from_secs(1)).await;
                    }
                }));
            }
            // we now enter the usual feeding loop
            log::info!(
                "listening on {}@{}:{}",
                hex::encode(ctx.sosistab2_sk.to_public().as_bytes()),
                if listen_addr.ip().is_unspecified() {
                    IpAddr::from(*MY_PUBLIC_IP)
                } else {
                    listen_addr.ip()
                },
                listen_addr.port()
            );

            loop {
                let pipe = udp_listener
                    .accept_pipe()
                    .race(tls_listener.accept_pipe())
                    .await?;
                if let Some(client) = ctx.stat_client.as_ref() {
                    handle_pipe_v2(
                        ctx.clone(),
                        StatsPipe::new(pipe, client.clone(), flow_key.clone()),
                    );
                } else {
                    handle_pipe_v2(ctx.clone(), pipe);
                }
            }
        })
    };

    // race
    control_prot_fut.or(gauge_fut).or(pipe_listen_fut).await
}
