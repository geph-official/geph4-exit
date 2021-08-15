use std::{io::Read, sync::Arc};

use anyhow::Context;
use config::Config;
use env_logger::Env;

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

iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE --random
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
