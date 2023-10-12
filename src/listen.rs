use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering,
    time::{Duration, Instant, SystemTime},
};

use crate::{
    asn::MY_PUBLIC_IP, config::CONFIG, listen::control::dummy_tls_config, ratelimit::BW_MULTIPLIER,
    root_ctx::ROOT_CTX, stats_pipe::StatsPipe, vpn,
};

use anyhow::Context;
use bytes::Bytes;
use ed25519_dalek::{ed25519::signature::Signature, Signer};

use geph4_protocol::{binder::protocol::BridgeDescriptor, bridge_exit::serve_bridge_exit};

use smol::prelude::*;

use sosistab2::{ObfsTlsListener, ObfsUdpListener, ObfsUdpSecret, PipeListener};
use sysinfo::{CpuExt, System, SystemExt};

use self::{control::ControlService, session_v2::handle_pipe_v2};

mod control;
mod session_v2;

/// the main listening loop
pub async fn main_loop() -> anyhow::Result<()> {
    smolscale::spawn(idlejitter())
        .race(smolscale::spawn(killconn()))
        .race(smolscale::spawn(vpn::transparent_proxy_helper()))
        .race(smolscale::spawn(control_protocol()))
        .race(smolscale::spawn(run_gauges()))
        .race(smolscale::spawn(pipe_listen()))
        .race(smolscale::spawn(set_ratelimit_loop()))
        .await
}

async fn idlejitter() -> anyhow::Result<()> {
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
                    .context("wtf")?
                    .timer(&key, elapsed.as_secs_f64() * 1000.0);
            }
        }
    }
}

async fn killconn() -> anyhow::Result<()> {
    loop {
        if ROOT_CTX.conn_count.load(Ordering::Relaxed) > CONFIG.conn_count_limit() {
            ROOT_CTX
                .kill_event
                .notify_relaxed(CONFIG.conn_count_limit() / 8)
        }
        smol::Timer::after(Duration::from_secs(5)).await;
    }
}

async fn control_protocol() -> anyhow::Result<()> {
    if CONFIG.official().is_some() {
        let secret = blake3::hash(dbg!(CONFIG
            .official()
            .as_ref()
            .unwrap()
            .bridge_secret()
            .as_bytes()));
        log::debug!("bridge secret {:?}", secret);
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
}

async fn run_gauges() -> anyhow::Result<()> {
    let key = format!("session_count.{}", ROOT_CTX.exit_hostname_dashed());
    let memkey = format!("bytes_allocated.{}", ROOT_CTX.exit_hostname_dashed());
    let connkey = format!("conn_count.{}", ROOT_CTX.exit_hostname_dashed());
    let threadkey = format!("thread_key.{}", ROOT_CTX.exit_hostname_dashed());
    let ctrlkey = format!("control_count.{}", ROOT_CTX.exit_hostname_dashed());
    let taskkey = format!("task_count.{}", ROOT_CTX.exit_hostname_dashed());

    let cpukey = format!("cpu_usage.{}", ROOT_CTX.exit_hostname_dashed());
    let loadkey = format!("load_factor.{}", ROOT_CTX.exit_hostname_dashed());
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
            let conn_count = ROOT_CTX.conn_count.load(Ordering::Relaxed);
            stat_client.gauge(&connkey, conn_count as f64);
            let control_count = ROOT_CTX.control_count.load(Ordering::Relaxed);
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
}

async fn pipe_listen() -> anyhow::Result<()> {
    let exit_hostname = CONFIG
        .official()
        .as_ref()
        .map(|official| official.exit_hostname().to_owned())
        .unwrap_or_default();
    let exit_hostname2 = exit_hostname.to_string();
    let bridge_pkt_key = move |bridge_group: &str| {
        format!(
            "raw_flow.{}.{}",
            exit_hostname2.replace('.', "-"),
            bridge_group.replace('.', "-")
        )
    };

    // TODO this key reuse is *probably* fine security-wise, but we might wanna switch this to something else
    // This hack allows the client to deterministically get the correct ObfsUdpPublic, which is important for selfhosted instances having constant keys.
    let secret = ObfsUdpSecret::from_bytes(ROOT_CTX.sosistab2_sk.to_bytes());
    let listen_addr = CONFIG
        .sosistab2_listen()
        .parse()
        .expect("cannot parse sosistab2 listening address");

    let udp_listener = ObfsUdpListener::bind(listen_addr, secret.clone()).unwrap();
    let tls_cookie = Bytes::copy_from_slice(secret.to_public().as_bytes());
    let tls_listener = ObfsTlsListener::bind(listen_addr, dummy_tls_config(), tls_cookie.clone())
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
                        endpoint: SocketAddr::new((*MY_PUBLIC_IP).into(), listen_addr.port()),
                        cookie: secret.to_public().as_bytes().to_vec().into(),
                        exit_hostname: CONFIG.official().as_ref().unwrap().exit_hostname().into(),
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
                        endpoint: SocketAddr::new((*MY_PUBLIC_IP).into(), listen_addr.port()),
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
            handle_pipe_v2(StatsPipe::new(pipe, client.clone(), bridge_pkt_key("SELF")));
        } else {
            handle_pipe_v2(pipe);
        }
    }
}

async fn set_ratelimit_loop() -> anyhow::Result<()> {
    let iface_name = CONFIG
        .nat_external_iface()
        .clone()
        .unwrap_or_else(|| String::from("lo"));
    let all_limit = *CONFIG.all_limit() as f64;
    let mut sys = System::new_all();
    let mut i = 0.0;
    let target_usage = 0.95f32;
    let mut divider;
    let seconds = 10.0;
    let mut timer = smol::Timer::interval(Duration::from_secs_f64(seconds));
    let mut last_bw_used = 0u128;
    loop {
        let first_time = last_bw_used == 0;
        timer.next().await;
        sys.refresh_all();
        let cpus = sys.cpus();
        let cpu_usage = cpus.iter().map(|c| c.cpu_usage() / 100.0).sum::<f32>() / cpus.len() as f32;
        let bw_used: u128 = String::from_utf8_lossy(&std::fs::read(format!(
            "/sys/class/net/{iface_name}/statistics/tx_bytes"
        ))?)
        .trim()
        .parse()?;
        let bw_delta = bw_used.saturating_sub(last_bw_used);

        if let Some(client) = ROOT_CTX.stat_client.as_ref() {
            if !first_time {
                let stat_key = format!("raw_exit_usage.{}", ROOT_CTX.exit_hostname_dashed());
                client.count(&stat_key, bw_delta as f64);
            }
        }

        last_bw_used = bw_used;
        let bw_usage = (bw_delta as f64 / 1000.0 / all_limit / seconds) as f32;
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
        ROOT_CTX
            .load_factor
            .store(total_usage as f64 * multiplier, Ordering::Relaxed);
    }
}
