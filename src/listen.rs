use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use crate::{
    asn::MY_PUBLIC_IP,
    config::CONFIG,
    listen::control::dummy_tls_config,
    ratelimit::{BW_MULTIPLIER},
    root_ctx::ROOT_CTX,
    stats::StatsPipe,
    vpn,
};

use bytes::Bytes;
use ed25519_dalek::{ed25519::signature::Signature, Signer};


use geph4_protocol::{
    binder::{
        protocol::{BridgeDescriptor},
    },
    bridge_exit::serve_bridge_exit,
};



use smol::{prelude::*};

use sosistab2::{ObfsTlsListener, ObfsUdpListener, ObfsUdpSecret, PipeListener};
use sysinfo::{CpuExt, System, SystemExt};

use self::{control::ControlService, session_v2::handle_pipe_v2};

mod control;

mod session_v2;

async fn idlejitter() {
    const INTERVAL: Duration = Duration::from_millis(10);
    loop {
        let start = Instant::now();
        smol::Timer::after(INTERVAL).await;
        let elapsed = start.elapsed();
        if let Some(official) = CONFIG.official() {
            if rand::random::<f32>() < 0.01 {
                let key = format!("idlejitter.{}", official.exit_hostname().replace('.', "-"));
                ROOT_CTX
                    .stat_client
                    .as_ref()
                    .as_ref()
                    .unwrap()
                    .timer(&key, elapsed.as_secs_f64() * 1000.0);
            }
        }
    }
}

async fn killconn() {
    loop {
        if ROOT_CTX.conn_count.load(Ordering::Relaxed) > CONFIG.conn_count_limit() {
            ROOT_CTX
                .kill_event
                .notify_relaxed(CONFIG.conn_count_limit() / 8)
        }
        smol::Timer::after(Duration::from_secs(5)).await;
    }
}

/// the main listening loop
pub async fn main_loop() -> anyhow::Result<()> {
    let exit_hostname = CONFIG
        .official()
        .as_ref()
        .map(|official| official.exit_hostname().to_owned())
        .unwrap_or_default();
    let _idlejitter = smolscale::spawn(idlejitter());
    let _killconn = smolscale::spawn(killconn());
    let _vpn = smolscale::spawn(vpn::transparent_proxy_helper());

    // control protocol listener
    // future that governs the control protocol
    let control_prot_fut = async {
        if CONFIG.official().is_some() {
            let secret = blake3::hash(
                CONFIG
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
                geph4_protocol::bridge_exit::BridgeExitService(ControlService::new()),
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

            if let Some(stat_client) = ROOT_CTX.stat_client.as_ref() {
                let cpus = sys.cpus();
                let usage = cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32;

                let session_count = ROOT_CTX.session_counter.count();
                stat_client.gauge(&key, session_count as f64);

                let memory_usage = sys.total_memory() - sys.available_memory();
                stat_client.gauge(&memkey, memory_usage as f64);
                let conn_count = ROOT_CTX
                    .conn_count
                    .load(std::sync::atomic::Ordering::Relaxed);
                stat_client.gauge(&connkey, conn_count as f64);
                let control_count = ROOT_CTX
                    .control_count
                    .load(std::sync::atomic::Ordering::Relaxed);
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
        let flow_key = bridge_pkt_key("SELF");
        smolscale::spawn(async move {
            // TODO this key reuse is *probably* fine security-wise, but we might wanna switch this to something else
            // This hack allows the client to deterministically get the correct ObfsUdpPublic, which is important for selfhosted instances having constant keys.
            let secret = ObfsUdpSecret::from_bytes(ROOT_CTX.sosistab2_sk.to_bytes());
            let listen_addr = CONFIG
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
            if let Some(client) = ROOT_CTX.binder_client.clone() {
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
                                exit_hostname: CONFIG
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
                            let sig = ROOT_CTX
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
                                exit_hostname: ROOT_CTX.exit_hostname().into(),
                                alloc_group: "direct".into(),
                                update_time: SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                exit_signature: Bytes::new(),
                            };
                            let sig = ROOT_CTX
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
                hex::encode(ROOT_CTX.sosistab2_sk.to_public().as_bytes()),
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
                if let Some(client) = ROOT_CTX.stat_client.as_ref() {
                    handle_pipe_v2(StatsPipe::new(pipe, client.clone(), flow_key.clone()));
                } else {
                    handle_pipe_v2(pipe);
                }
            }
        })
    };

    // race
    control_prot_fut.or(gauge_fut).or(pipe_listen_fut).await
}
