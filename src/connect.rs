use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::{listen::RootCtx, ratelimit::RateLimiter};
use smol::io::{AsyncRead, AsyncWrite};
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use tap::TapFallible;

#[cached::proc_macro::cached(time = 600, result = true)]
async fn resolve_name_inner(name: String) -> anyhow::Result<SocketAddr> {
    Ok(smol::net::resolve(&name)
        .await?
        .into_iter()
        .find(|v| v.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("no IPv4 address"))?)
}

async fn resolve_name(name: String) -> anyhow::Result<SocketAddr> {
    for _ in 0..3 {
        if let Ok(a) = resolve_name_inner(name.clone()).await {
            return Ok(a);
        }
    }
    resolve_name_inner(name.clone()).await
}

/// Connects to a remote host and forwards traffic to/from it and a given client.
pub async fn proxy_loop(
    ctx: Arc<RootCtx>,
    rate_limit: Arc<RateLimiter>,
    client: impl AsyncRead + AsyncWrite + Clone + Unpin,
    addr: String,
    count_stats: bool,
) -> anyhow::Result<()> {
    // Incr/decr the connection count
    ctx.conn_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _deferred = scopeguard::guard((), |_| {
        ctx.conn_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    });

    // First, we establish a TCP connection
    let addr = resolve_name(addr.clone())
        .await
        .tap_err(|err| log::warn!("cannot resolve remote {}: {}", addr, err))?;

    // Reject if blacklisted
    if crate::lists::BLACK_PORTS.contains(&addr.port()) {
        anyhow::bail!("port blacklisted")
    }
    if ctx.config.port_whitelist() && !crate::lists::WHITE_PORTS.contains(&addr.port()) {
        anyhow::bail!("port not whitelisted")
    }

    // Obtain ASN
    let asn = crate::asn::get_asn(addr.ip());
    log::trace!(
        "got connection request to {} of AS{} (conn_count = {})",
        ctx.config.redact(addr),
        ctx.config.redact(asn),
        ctx.conn_count.load(std::sync::atomic::Ordering::Relaxed)
    );

    // Upload official stats
    let upload_stat = {
        let ctx = ctx.clone();
        let key = if let Some(off) = ctx.config.official() {
            format!("exit_usage.{}", off.exit_hostname().replace(".", "-"))
        } else {
            "".into()
        };
        move |n| {
            if fastrand::f32() < 0.01 && count_stats {
                if let Some(op) = ctx.stat_client.as_ref().as_ref() {
                    op.count(&key, n as f64 * 100.0)
                }
            }
        }
    };

    // Redirect if the config tells us to
    let addr = if addr.port() != 443 {
        addr
    } else if let Some(redirect_to) = ctx
        .config
        .asn_sniproxies()
        .as_ref()
        .and_then(|f| f.get(&asn.to_string()))
    {
        log::trace!("redirecting {} of AS{} to {}!", addr, asn, redirect_to);
        *redirect_to
    } else {
        addr
    };
    let remote = smol::net::TcpStream::connect(addr)
        .timeout(Duration::from_secs(60))
        .await
        .ok_or_else(|| anyhow::anyhow!("connect timed out"))??;
    remote.set_nodelay(true)?;
    let remote2 = remote.clone();
    let client2 = client.clone();
    smol::future::race(
        geph4_aioutils::copy_with_stats_async(remote2, client2, |n| {
            upload_stat(n);
            let rate_limit = rate_limit.clone();
            async move {
                rate_limit.wait(n).await;
            }
        }),
        geph4_aioutils::copy_with_stats(client, remote, |n| {
            upload_stat(n);
        }),
    )
    .or(async {
        // 30 second "grace period"
        smol::Timer::after(Duration::from_secs(30)).await;
        let killer = ctx.kill_event.listen();
        killer.await;
        log::warn!("killing connection due to connection kill event");
        Ok(())
    })
    .await?;
    Ok(())
}
