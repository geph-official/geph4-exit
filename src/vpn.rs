use bytes::Bytes;
use cidr::{Cidr, Ipv4Cidr};

use futures_util::TryFutureExt;
use libc::{c_void, SOL_IP, SO_ORIGINAL_DST};

use once_cell::sync::Lazy;
use os_socketaddr::OsSocketAddr;
use parking_lot::{Mutex, RwLock};
use pnet_packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet,
};
use rand::prelude::*;
use smol::channel::Sender;
use sosistab::{Buff, BuffMut};

use geph4_protocol::VpnMessage;
use std::{collections::BTreeMap, ops::DerefMut, os::unix::io::AsRawFd};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    ops::Deref,
    sync::Arc,
};
use tundevice::TunDevice;

use crate::{connect::proxy_loop, listen::RootCtx, ratelimit::RateLimiter};

/// Runs the transparent proxy helper
pub async fn transparent_proxy_helper(ctx: Arc<RootCtx>) -> anyhow::Result<()> {
    if ctx.config.nat_external_iface().is_none() {
        return Ok(());
    }
    // always run on port 10000
    // TODO this should bind dynamically
    let listen_addr: SocketAddr = "0.0.0.0:10000".parse().unwrap();
    let listener = smol::Async::<std::net::TcpListener>::bind(listen_addr).unwrap();

    loop {
        let (client, _) = listener.accept().await.unwrap();
        let ctx = ctx.clone();
        let rate_limit = Arc::new(RateLimiter::unlimited());
        let conn_task = smolscale::spawn(
            async move {
                let client_fd = client.as_raw_fd();
                let addr = unsafe {
                    let raw_addr = OsSocketAddr::new();
                    if libc::getsockopt(
                        client_fd,
                        SOL_IP,
                        SO_ORIGINAL_DST,
                        raw_addr.as_ptr() as *mut c_void,
                        (&mut std::mem::size_of::<libc::sockaddr>()) as *mut usize as *mut u32,
                    ) != 0
                    {
                        anyhow::bail!("cannot get SO_ORIGINAL_DST, aborting");
                    };
                    let lala = raw_addr.into_addr();
                    if let Some(lala) = lala {
                        lala
                    } else {
                        anyhow::bail!("SO_ORIGINAL_DST is not an IP address, aborting");
                    }
                };
                let client = async_dup::Arc::new(client);
                client.get_ref().set_nodelay(true)?;
                proxy_loop(ctx, rate_limit, client, addr.to_string(), false).await
            }
            .map_err(|e| log::trace!("vpn conn closed: {}", e)),
        );
        conn_task.detach();
    }
}

/// Handles a VPN session
pub async fn handle_vpn_session(
    ctx: Arc<RootCtx>,
    mux: Arc<sosistab::Multiplex>,
    rate_limit: Arc<RateLimiter>,
    on_activity: impl Fn(),
) -> anyhow::Result<()> {
    if ctx.config.nat_external_iface().is_none() {
        log::warn!("disabling VPN mode since external interface is not specified!");
        return smol::future::pending().await;
    }
    Lazy::force(&INCOMING_PKT_HANDLER);
    log::trace!("handle_vpn_session entered");
    scopeguard::defer!(log::trace!("handle_vpn_session exited"));

    // set up IP address allocation
    let assigned_ip: Lazy<AssignedIpv4Addr> = Lazy::new(|| IpAddrAssigner::global().assign());
    let addr = assigned_ip.addr();
    scopeguard::defer!({
        INCOMING_MAP.write().remove(&addr);
    });
    let stat_key = format!(
        "exit_usage.{}",
        ctx.config
            .official()
            .as_ref()
            .map(|official| official.exit_hostname().to_string())
            .unwrap_or_default()
            .replace(".", "-")
    );

    let (send_down, recv_down) =
        smol::channel::bounded(if rate_limit.is_unlimited() { 4096 } else { 64 });
    INCOMING_MAP.write().insert(addr, send_down);
    let _down_task: smol::Task<anyhow::Result<()>> = {
        let stat_key = stat_key.clone();
        let ctx = ctx.clone();
        let mux = mux.clone();
        smolscale::spawn(async move {
            loop {
                let bts = recv_down.recv().await?;
                if let Some(stat_client) = ctx.stat_client.as_ref() {
                    if fastrand::f32() < 0.01 {
                        stat_client.count(&stat_key, bts.len() as f64 * 100.0)
                    }
                }
                rate_limit.wait(bts.len()).await;
                let pkt = Ipv4Packet::new(&bts).expect("don't send me invalid IPv4 packets!");
                assert_eq!(pkt.get_destination(), addr);
                let msg = VpnMessage::Payload(Bytes::copy_from_slice(&bts));
                let mut to_send = BuffMut::new();
                bincode::serialize_into(to_send.deref_mut(), &msg).unwrap();
                let _ = mux.send_urel(to_send).await;
            }
        })
    };

    loop {
        let bts = mux.recv_urel().await?;
        on_activity();
        let msg: VpnMessage = bincode::deserialize(&bts)?;
        match msg {
            VpnMessage::ClientHello { .. } => {
                mux.send_urel(
                    bincode::serialize(&VpnMessage::ServerHello {
                        client_ip: *assigned_ip.clone(),
                        gateway: "100.64.0.1".parse().unwrap(),
                    })
                    .unwrap()
                    .as_slice(),
                )
                .await?;
            }
            VpnMessage::Payload(bts) => {
                if let Some(stat_client) = ctx.stat_client.as_ref() {
                    if fastrand::f32() < 0.01 {
                        stat_client.count(&stat_key, bts.len() as f64 * 100.0)
                    }
                }
                let pkt = Ipv4Packet::new(&bts);
                if let Some(pkt) = pkt {
                    // source must be correct and destination must not be banned
                    if pkt.get_source() != assigned_ip.addr()
                        || pkt.get_destination().is_loopback()
                        || pkt.get_destination().is_private()
                        || pkt.get_destination().is_unspecified()
                        || pkt.get_destination().is_broadcast()
                    {
                        continue;
                    }
                    // must not be blacklisted
                    let port = {
                        match pkt.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                TcpPacket::new(pkt.payload()).map(|v| v.get_destination())
                            }
                            IpNextHeaderProtocols::Udp => {
                                UdpPacket::new(pkt.payload()).map(|v| v.get_destination())
                            }
                            _ => None,
                        }
                    };
                    if let Some(port) = port {
                        if crate::lists::BLACK_PORTS.contains(&port) {
                            continue;
                        }
                        if ctx.config.port_whitelist() && !crate::lists::WHITE_PORTS.contains(&port)
                        {
                            continue;
                        }
                    }
                    RAW_TUN.write_raw(&bts).await;
                }
            }
            _ => anyhow::bail!("message in invalid context"),
        }
    }
}

/// Mapping for incoming packets
#[allow(clippy::type_complexity)]
static INCOMING_MAP: Lazy<RwLock<BTreeMap<Ipv4Addr, Sender<Buff>>>> = Lazy::new(Default::default);

/// Incoming packet handler
static INCOMING_PKT_HANDLER: Lazy<smol::Task<()>> = Lazy::new(|| {
    smolscale::spawn(async {
        let mut buf = [0; 2048];
        loop {
            let n = RAW_TUN
                .read_raw(&mut buf)
                .await
                .expect("cannot read from tun device");
            let pkt = &buf[..n];
            if rand::random::<f32>() < 0.1 {
                smol::future::yield_now().await;
            }
            let map = INCOMING_MAP.read();
            let dest = Ipv4Packet::new(pkt).map(|pkt| map.get(&pkt.get_destination()));
            if let Some(Some(dest)) = dest {
                let _ = dest.try_send(pkt.into());
            }
        }
    })
});

/// The raw TUN device.
static RAW_TUN: Lazy<TunDevice> = Lazy::new(|| {
    log::info!("initializing tun-geph");
    let dev =
        TunDevice::new_from_os("tun-geph").expect("could not initiate 'tun-geph' tun device!");
    dev.assign_ip("100.64.0.1/10");
    smol::future::block_on(dev.write_raw(b"hello world"));
    dev
});

/// Global IpAddr assigner
static CGNAT_IPASSIGN: Lazy<IpAddrAssigner> =
    Lazy::new(|| IpAddrAssigner::new("100.64.0.0/10".parse().unwrap()));

/// An IP address assigner
pub struct IpAddrAssigner {
    cidr: Ipv4Cidr,
    table: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl IpAddrAssigner {
    /// Creates a new address assigner.
    pub fn new(cidr: Ipv4Cidr) -> Self {
        Self {
            cidr,
            table: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Get the global CGNAT instance.
    pub fn global() -> &'static Self {
        &CGNAT_IPASSIGN
    }

    /// Assigns a new IP address.
    pub fn assign(&self) -> AssignedIpv4Addr {
        let first = u32::from_be_bytes(self.cidr.first_address().octets());
        let last = u32::from_be_bytes(self.cidr.last_address().octets());
        loop {
            let candidate = rand::thread_rng().gen_range(first + 16, last - 16);
            let candidate = Ipv4Addr::from(candidate);
            let mut tab = self.table.lock();
            if !tab.contains(&candidate) {
                tab.insert(candidate);
                log::trace!("assigned {}", candidate);
                return AssignedIpv4Addr::new(self.table.clone(), candidate);
            }
        }
    }
}

/// An assigned IP address. Derefs to std::net::Ipv4Addr and acts as a smart-pointer that deassigns the IP address when no longer needed.
#[derive(Clone, Debug)]
pub struct AssignedIpv4Addr {
    inner: Arc<AssignedIpv4AddrInner>,
}

impl AssignedIpv4Addr {
    fn new(table: Arc<Mutex<HashSet<Ipv4Addr>>>, addr: Ipv4Addr) -> Self {
        Self {
            inner: Arc::new(AssignedIpv4AddrInner { addr, table }),
        }
    }
    pub fn addr(&self) -> Ipv4Addr {
        self.inner.addr
    }
}

impl PartialEq for AssignedIpv4Addr {
    fn eq(&self, other: &Self) -> bool {
        self.inner.addr.eq(&other.inner.addr)
    }
}

impl Eq for AssignedIpv4Addr {}

impl PartialOrd for AssignedIpv4Addr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner.addr.partial_cmp(&other.inner.addr)
    }
}

impl Ord for AssignedIpv4Addr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.addr.cmp(&other.inner.addr)
    }
}

impl Deref for AssignedIpv4Addr {
    type Target = Ipv4Addr;

    fn deref(&self) -> &Self::Target {
        &self.inner.addr
    }
}

#[derive(Debug)]
struct AssignedIpv4AddrInner {
    addr: Ipv4Addr,
    table: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl Drop for AssignedIpv4AddrInner {
    fn drop(&mut self) {
        log::trace!("dropped {}", self.addr);
        if !self.table.lock().remove(&self.addr) {
            panic!("AssignedIpv4Addr double free?! {}", self.addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgnat() {
        let assigner = IpAddrAssigner::new("100.64.0.0/10".parse().unwrap());
        let mut assigned = Vec::new();
        for _ in 0..2 {
            assigned.push(assigner.assign());
        }
        dbg!(assigned);
    }
}
