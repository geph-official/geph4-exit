use std::{
    io::{Read, Write},
    sync::Arc,
};

use anyhow::Context;
use config::Config;
use env_logger::Env;

use flate2::{write::GzEncoder, Compression};
use jemallocator::Jemalloc;

use structopt::StructOpt;

use crate::listen::{main_loop, RootCtx};

mod asn;
mod config;
mod connect;
mod listen;
mod lists;
mod ratelimit;
mod vpn;

#[derive(Debug, StructOpt, Clone)]
struct Opt {
    #[structopt(long)]
    /// Path to configuration file. Can be a HTTP URL!
    config: String,
}

#[global_allocator]
pub static ALLOCATOR: Jemalloc = Jemalloc;

fn main() -> anyhow::Result<()> {
    if std::env::var("GEPH_SINGLETHREADED").is_ok() {
        smolscale::permanently_single_threaded();
    }
    env_logger::Builder::from_env(Env::default().default_filter_or("geph4_exit=debug,warn")).init();
    let opt = Opt::from_args();
    let config: Config = {
        if opt.config.starts_with("http") {
            let resp = ureq::get(&opt.config).call();
            let mut buf = Vec::new();
            resp.into_reader()
                .read_to_end(&mut buf)
                .context("cannot download configuration file")?;
            toml::from_slice(&buf).context("cannot parse downloaded configuration file")?
        } else {
            toml::from_slice(&std::fs::read(&opt.config).context("cannot read configuration file")?)
                .context("cannot parse configuration file")?
        }
    };
    log::info!(
        "read configuration file:\n{}",
        serde_json::to_string_pretty(&config)?
    );

    if let Some(trace) = config.sosistab_trace().as_ref() {
        let (send, recv) = flume::unbounded();
        log::info!("writing gzipped sosistab traces to {:?}", trace);
        sosistab::init_packet_tracing(move |line| send.send(line).unwrap());
        let trace = trace.clone();
        std::thread::Builder::new()
            .name("trace-writer".into())
            .spawn(move || {
                let file = std::fs::File::create(&trace).expect("cannot create trace file");
                let mut file = GzEncoder::new(file, Compression::best());
                loop {
                    let line = recv.recv().unwrap();
                    writeln!(file, "{}", line).expect("cannot write line to file");
                }
            })
            .unwrap();
    }

    if let Some(nat_interface) = config.nat_external_iface().as_ref() {
        config_iptables(nat_interface)?;
    }
    let ctx: RootCtx = config.into();
    smolscale::block_on(main_loop(Arc::new(ctx)))
}

/// Configures iptables.
fn config_iptables(nat_interface: &str) -> anyhow::Result<()> {
    let to_run = format!(
        r#"
    #!/bin/sh
export INTERFACE={}

iptables --flush
iptables -t nat -F

iptables -t nat -A PREROUTING -i tun-geph -p tcp --syn -j REDIRECT --match multiport --dports 80,443,8080 --to-ports 10000

iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE --random-fully
iptables -A FORWARD -i $INTERFACE -o tun-geph -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i tun-geph -o $INTERFACE -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
"#,
        nat_interface
    );
    let mut cmd = std::process::Command::new("sh")
        .arg("-c")
        .arg(&to_run)
        .spawn()?;
    cmd.wait()?;
    Ok(())
}
