use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use atomic_float::AtomicF64;
use event_listener::Event;
use futures_util::StreamExt;
use geph4_protocol::binder::{client::E2eeHttpTransport, protocol::BinderClient};
use moka::sync::Cache;
use once_cell::sync::Lazy;
use smol::{fs::unix::PermissionsExt, Task};
use sosistab2::MuxSecret;
use sysinfo::{CpuExt, System, SystemExt};

use crate::{
    amnesiac_counter::AmnesiacCounter,
    config::CONFIG,
    ratelimit::{RateLimiter, BW_MULTIPLIER},
};

/// the root context
pub struct RootCtx {
    pub stat_client: Option<Arc<statsd::Client>>,
    pub binder_client: Option<Arc<BinderClient>>,
    pub signing_sk: ed25519_dalek::Keypair,

    pub sosistab2_sk: MuxSecret,

    pub session_counter: AmnesiacCounter,
    pub conn_count: AtomicUsize,
    pub control_count: AtomicUsize,

    pub kill_event: Event,

    pub load_factor: Arc<AtomicF64>,

    pub mass_ratelimits: Cache<u64, RateLimiter>,

    _task: Task<()>,
}

pub static ROOT_CTX: Lazy<RootCtx> = Lazy::new(|| {
    let sosistab2_sk = {
        match std::fs::read(CONFIG.secret_sosistab2_key()) {
            Ok(vec) => bincode::deserialize(&vec).expect("failed to deserialize my own secret key"),
            Err(err) => {
                log::warn!(
                    "can't read signing_sk, so creating one and saving it! {}",
                    err
                );
                let new_keypair = MuxSecret::generate();
                if let Err(err) = std::fs::write(
                    CONFIG.secret_sosistab2_key(),
                    bincode::serialize(&new_keypair).unwrap(),
                ) {
                    log::error!("cannot save signing_sk persistently!!! {}", err);
                } else {
                    let mut perms = std::fs::metadata(CONFIG.secret_sosistab2_key())
                        .unwrap()
                        .permissions();
                    perms.set_readonly(true);
                    perms.set_mode(0o600);
                    std::fs::set_permissions(CONFIG.secret_sosistab2_key(), perms).unwrap();
                }
                new_keypair
            }
        }
    };
    let signing_sk = {
        match std::fs::read(CONFIG.secret_key()) {
            Ok(vec) => bincode::deserialize(&vec).expect("failed to deserialize my own secret key"),
            Err(err) => {
                log::warn!(
                    "can't read signing_sk, so creating one and saving it! {}",
                    err
                );
                let new_keypair = ed25519_dalek::Keypair::generate(&mut rand::rngs::OsRng {});
                if let Err(err) = std::fs::write(
                    CONFIG.secret_key(),
                    bincode::serialize(&new_keypair).unwrap(),
                ) {
                    log::error!("cannot save signing_sk persistently!!! {}", err);
                } else {
                    let mut perms = std::fs::metadata(CONFIG.secret_key())
                        .unwrap()
                        .permissions();
                    perms.set_readonly(true);
                    perms.set_mode(0o600);
                    std::fs::set_permissions(CONFIG.secret_key(), perms).unwrap();
                }
                new_keypair
            }
        }
    };
    log::info!("signing_sk = {}", hex::encode(signing_sk.public));

    let load_factor = Arc::new(AtomicF64::new(0.0));
    let stat_client = CONFIG
        .official()
        .as_ref()
        .map(|official| Arc::new(statsd::Client::new(official.statsd_addr(), "geph4").unwrap()));
    RootCtx {
        stat_client,
        binder_client: CONFIG.official().as_ref().map(|official| {
            let bclient: Arc<BinderClient> = Arc::new(BinderClient::from(E2eeHttpTransport::new(
                bincode::deserialize(
                    &hex::decode(official.binder_master_pk()).expect("invalid hex in binder pk"),
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
            CONFIG
                .nat_external_iface()
                .clone()
                .unwrap_or_else(|| String::from("lo")),
            *CONFIG.all_limit(),
        )),
    }
});

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
        CONFIG
            .official()
            .as_ref()
            .map(|official| official.exit_hostname().to_owned())
            .unwrap_or_default()
            .replace('.', "-")
    }

    pub fn exit_hostname(&self) -> String {
        CONFIG
            .official()
            .as_ref()
            .map(|official| official.exit_hostname().to_owned())
            .unwrap_or_default()
    }

    pub fn get_ratelimit(&self, key: u64, free: bool) -> RateLimiter {
        if free {
            self.mass_ratelimits.get_with(key, || {
                RateLimiter::new(
                    CONFIG
                        .official()
                        .as_ref()
                        .and_then(|s| *s.free_limit())
                        .unwrap_or_default(),
                    1024,
                )
            })
        } else if CONFIG
            .official()
            .as_ref()
            .and_then(|s| *s.free_limit())
            .unwrap_or_default()
            > 0
        {
            // plus on free
            self.mass_ratelimits
                .get_with(key.rotate_left(3), || RateLimiter::new(1903, 5_000_000))
        } else {
            RateLimiter::unlimited()
        }
    }
}
