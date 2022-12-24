use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
};

use super::SessCtx;
use crate::{connect::proxy_loop, vpn::handle_vpn_session};

use futures_util::TryFutureExt;
use geph4_protocol::binder::protocol::{BinderClient, BlindToken, Level};
use rand::Rng;
use smol::prelude::*;
use smol_timeout::TimeoutExt;

use std::sync::Arc;

pub async fn handle_session_legacy(ctx: SessCtx) {
    let fallible = async move {
        log::debug!("entering handle_session");
        let SessCtx { root, sess } = ctx;

        // raw session count
        root.raw_session_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _guard = scopeguard::guard((), |_| {
            root.raw_session_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });

        let sess = Arc::new(sosistab::Multiplex::new(sess));
        let is_plus = if let Some(binder_client) = root.binder_client.as_ref() {
            log::debug!("attempting to authenticate because we do have a binder_client");
            authenticate_sess(binder_client.clone(), &sess)
                .timeout(Duration::from_secs(30))
                .await
                .ok_or_else(|| anyhow::anyhow!("authentication timeout"))??
        } else {
            true
        };
        log::info!(
            "authenticated a new session (is_plus = {}, raw_session_count = {})",
            is_plus,
            root.raw_session_count.load(Ordering::Relaxed)
        );

        let rate_limit = if let Some(official) = root.config.official() {
            if !is_plus {
                let free_limit = official.free_limit().unwrap_or_default();
                if free_limit == 0 {
                    anyhow::bail!("not accepting free users here")
                } else {
                    root.get_ratelimit(fastrand::u64(..), true)
                }
            } else {
                root.get_ratelimit(fastrand::u64(..), false)
            }
        } else {
            root.get_ratelimit(fastrand::u64(..), false)
        };
        let rate_limit = Arc::new(rate_limit);

        // we register an entry into the session replace table
        let sess_replace_key: [u8; 32] = rand::random();
        let (send_sess_replace, recv_sess_replace) = smol::channel::unbounded();
        root.sess_replacers
            .insert(sess_replace_key, send_sess_replace);
        scopeguard::defer!({
            root.sess_replacers.remove(&sess_replace_key);
        });

        let (send_sess_alive, recv_sess_alive) = smol::channel::bounded(1);
        let sess_alive_loop = {
            let recv_sess_alive = recv_sess_alive.clone();
            let root = root.clone();
            smolscale::spawn(async move {
                let alive = AtomicBool::new(false);
                let guard = scopeguard::guard(alive, |v| {
                    if v.load(Ordering::SeqCst) {
                        root.session_count
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                });
                loop {
                    let signal = recv_sess_alive
                        .recv()
                        .timeout(Duration::from_secs(600))
                        .await;
                    if let Some(sig) = signal {
                        sig?;
                        if !guard.swap(true, Ordering::SeqCst) {
                            root.session_count
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    } else if guard.swap(false, Ordering::SeqCst) {
                        root.session_count
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            })
        };

        let proxy_loop = {
            let root = root.clone();
            let sess = sess.clone();
            let rate_limit = rate_limit.clone();
            let send_sess_alive = send_sess_alive.clone();
            smolscale::spawn(async move {
                let client_id: u64 = rand::thread_rng().gen();
                loop {
                    let mut client = sess
                        .accept_conn()
                        .timeout(Duration::from_secs(3600))
                        .await
                        .ok_or_else(|| anyhow::anyhow!("accept timeout"))??;
                    let send_sess_alive = send_sess_alive.clone();
                    let root = root.clone();
                    let rate_limit = rate_limit.clone();
                    smolscale::spawn(
                        async move {
                            let addr = client.additional_info().unwrap_or_default().to_owned();
                            match addr.as_str() {
                                "" => {
                                    if let Some(stat) = root.stat_client.as_ref() {
                                        stat.count(
                                            &format!("watchdogs.{}", root.exit_hostname_dashed()),
                                            1.0,
                                        );
                                    }
                                }
                                "!id" => {
                                    // return the ID of this mux
                                    client.write_all(&sess_replace_key).await?;
                                }

                                _ => {
                                    let _ = send_sess_alive.try_send(());
                                    proxy_loop(root, rate_limit, client, client_id, addr, true)
                                        .await?
                                }
                            }
                            Ok(())
                        }
                        .map_err(|e: anyhow::Error| log::trace!("proxy conn closed: {}", e)),
                    )
                    .detach();
                }
            })
        };
        let vpn_loop = smolscale::spawn(handle_vpn_session(
            root.clone(),
            sess.clone(),
            rate_limit.clone(),
            move || {
                let _ = send_sess_alive.try_send(());
            },
        ));

        let sess_replace_loop = async {
            loop {
                let new_sess = recv_sess_replace.recv().await?;
                sess.replace_session(new_sess).await;
            }
        };

        Ok(((proxy_loop.or(sess_alive_loop)).race(vpn_loop))
            .or(sess_replace_loop)
            .await)
    };
    if let Err(err) = fallible.await {
        log::warn!("session exited with: {:?}", err)
    }
}

/// Authenticates a session.
async fn authenticate_sess(
    binder_client: Arc<BinderClient>,
    sess: &sosistab::Multiplex,
) -> anyhow::Result<bool> {
    let mut stream = sess.accept_conn().await?;
    log::debug!("authenticating session...");
    // wait for a message containing a blinded signature
    let (auth_tok, auth_sig, level): (Vec<u8>, mizaru::UnblindedSignature, String) =
        geph4_aioutils::read_pascalish(&mut stream).await?;
    if (auth_sig.epoch as i32 - mizaru::time_to_epoch(SystemTime::now()) as i32).abs() > 2 {
        anyhow::bail!("outdated authentication token")
    }
    let is_plus = level != "free";
    // validate it through the binder
    let validated = binder_client
        .validate(BlindToken {
            level: if level == "free" {
                Level::Free
            } else {
                Level::Plus
            },
            unblinded_digest: auth_tok.into(),
            unblinded_signature_bincode: bincode::serialize(&auth_sig)?.into(),
        })
        .await?;
    if !validated {
        anyhow::bail!(
            "unexpected authentication response from binder: {:?}",
            validated
        )
    }
    // send response
    geph4_aioutils::write_pascalish(&mut stream, &1u8).await?;
    Ok(is_plus)
}
