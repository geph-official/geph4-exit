use std::{
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
};

use atomic_float::AtomicF64;
use event_listener::Event;

use geph4_protocol::binder::{client::E2eeHttpTransport, protocol::BinderClient};
use moka::sync::Cache;
use once_cell::sync::Lazy;
use smol::fs::unix::PermissionsExt;
use sosistab2::MuxSecret;

use crate::{amnesiac_counter::AmnesiacCounter, config::CONFIG, ratelimit::RateLimiter};

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

        load_factor,

        session_counter: AmnesiacCounter::new(Duration::from_secs(300)),
        conn_count: Default::default(),
        control_count: Default::default(),

        kill_event: Event::new(),

        mass_ratelimits: Cache::builder()
            .time_to_idle(Duration::from_secs(86400))
            .build(),
    }
});

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
