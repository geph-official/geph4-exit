use std::{net::SocketAddr, ops::Deref};

use env_logger::Env;

use smol::process::Command;
use structopt::StructOpt;

use crate::{config::CONFIG, listen::main_loop};

mod amnesiac_counter;
mod asn;
mod config;
mod connect;
mod listen;
mod lists;
mod ratelimit;
mod smartchan;
mod stats;
mod vpn;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() -> anyhow::Result<()> {
    std::env::set_var("SOSISTAB_NO_OOB", "1");
    std::env::set_var("SOSISTAB_NO_FEC", "1");
    if std::env::var("GEPH_SINGLETHREADED").is_ok() {
        smolscale::permanently_single_threaded();
    }
    env_logger::Builder::from_env(Env::default().default_filter_or("geph4_exit=debug,warn")).init();

    log::info!(
        "read configuration file:\n{}",
        serde_json::to_string_pretty(&CONFIG.deref())?
    );

    if let Some(nat_interface) = CONFIG.nat_external_iface().as_ref() {
        config_iptables(
            nat_interface,
            *CONFIG.force_dns(),
            !CONFIG.disable_tcp_termination(),
        )?;
    }

    smolscale::block_on(async move {
        if let Some(range) = CONFIG.random_ipv6_range() {
            if let Some(iface) = CONFIG.ipv6_interface() {
                Command::new("ip")
                    .arg("-6")
                    .arg("route")
                    .arg("del")
                    .arg("local")
                    .arg(format!("{}", range))
                    .spawn()?
                    .output()
                    .await?;
                Command::new("ip")
                    .arg("-6")
                    .arg("route")
                    .arg("add")
                    .arg("local")
                    .arg(format!("{}", range))
                    .arg("dev")
                    .arg(iface)
                    .spawn()?
                    .output()
                    .await?;
            }
        }

        main_loop().await
    })
}

/// Configures iptables.
fn config_iptables(
    nat_interface: &str,
    force_dns: Option<SocketAddr>,
    tcp_redirect: bool,
) -> anyhow::Result<()> {
    let to_run = format!(
        r#"
    #!/bin/sh
export INTERFACE={}

iptables --flush
iptables -t nat -F
iptables -t mangle -F

{}
{}

iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE --random-fully
iptables -A FORWARD -i $INTERFACE -o tun-geph -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i tun-geph -o $INTERFACE -j ACCEPT
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
"#,
        nat_interface,
        if tcp_redirect {
            "iptables -t nat -A PREROUTING -i tun-geph -p tcp --syn -j REDIRECT --match multiport --dports 80,443,8080 --to-ports 10000"
        } else {
            ""
        },
        force_dns
            .map(|d| {
                format!(
                    "iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to {}",
                    d
                )
            })
            .unwrap_or_default()
    );
    let mut cmd = std::process::Command::new("sh")
        .arg("-c")
        .arg(&to_run)
        .spawn()?;
    cmd.wait()?;
    Ok(())
}
