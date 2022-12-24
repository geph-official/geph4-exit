use anyhow::Context;
use bytes::Bytes;

use cidr_utils::cidr::Ipv4Cidr;
use futures_util::TryFutureExt;
use libc::{c_void, SOL_IP, SO_ORIGINAL_DST};

use moka::sync::Cache;

use once_cell::sync::Lazy;
use os_socketaddr::OsSocketAddr;
use parking_lot::Mutex;
use pnet_packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet,
};
use rand::prelude::*;
use smol::channel::{Receiver, Sender};
use sosistab::BuffMut;

use geph4_protocol::VpnMessage;
use std::{
    collections::HashSet,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::{Deref, DerefMut},
    os::unix::prelude::{AsRawFd, FromRawFd},
    sync::Arc,
};
use tun::{platform::Device, Device as Device2};

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
        let rate_limit = Arc::new(RateLimiter::unlimited(None));
        let conn_task = smolscale::spawn(
            async move {
                static CLIENT_ID_CACHE: Lazy<Cache<IpAddr, u64>> =
                    Lazy::new(|| Cache::new(1_000_000));
                let peer_addr = client.as_ref().peer_addr().context("no peer addr")?.ip();
                let client_id = CLIENT_ID_CACHE.get_with(peer_addr, || rand::thread_rng().gen());
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
                client
                    .get_ref()
                    .set_nodelay(true)
                    .context("cannot set nodelay")?;
                proxy_loop(ctx, rate_limit, client, client_id, addr.to_string(), false).await
            }
            .map_err(|e| log::debug!("vpn conn closed: {:?}", e)),
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
    log::debug!("handle_vpn_session entered");
    scopeguard::defer!(log::trace!("handle_vpn_session exited"));

    // set up IP address allocation
    let assigned_ip: Lazy<AssignedIpv4Addr> = Lazy::new(|| IpAddrAssigner::global().assign());
    let addr = assigned_ip.addr();
    scopeguard::defer!({
        INCOMING_MAP.invalidate(&addr);
    });

    let recv_down = vpn_subscribe_down(assigned_ip.addr());
    let _down_task: smol::Task<anyhow::Result<()>> = {
        let ctx = ctx.clone();
        let mux = mux.clone();
        smolscale::spawn(async move {
            loop {
                let bts = recv_down.recv().await?;
                ctx.incr_throughput(bts.len());
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
                vpn_send_up(&ctx, assigned_ip.addr(), &bts).await;
            }
            _ => anyhow::bail!("message in invalid context"),
        }
    }
}

/// Subscribes to downstream packets
pub fn vpn_subscribe_down(addr: Ipv4Addr) -> Receiver<Bytes> {
    let (send_down, recv_down) = smol::channel::bounded(1000);
    INCOMING_MAP.insert(addr, send_down);
    recv_down
}

/// Writes a raw, upacket
pub async fn vpn_send_up(ctx: &RootCtx, assigned_ip: Ipv4Addr, bts: &[u8]) {
    ctx.incr_throughput(bts.len());
    let pkt = Ipv4Packet::new(bts);
    if let Some(pkt) = pkt {
        // source must be correct and destination must not be banned
        if pkt.get_source() != assigned_ip
            || pkt.get_destination().is_loopback()
            || pkt.get_destination().is_private()
            || pkt.get_destination().is_unspecified()
            || pkt.get_destination().is_broadcast()
        {
            return;
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
            // Block QUIC due to it performing badly over sosistab etc
            if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Udp && port == 443 {
                return;
            }
            if crate::lists::BLACK_PORTS.contains(&port) {
                return;
            }
            if ctx.config.port_whitelist() && !crate::lists::WHITE_PORTS.contains(&port) {
                return;
            }
        }
        RAW_TUN_WRITE(bts);
        smol::future::yield_now().await;
    }
}

/// Mapping for incoming packets
#[allow(clippy::type_complexity)]
static INCOMING_MAP: Lazy<Cache<Ipv4Addr, Sender<Bytes>>> =
    Lazy::new(|| Cache::builder().max_capacity(1_000_000).build());

/// The raw TUN device.
static RAW_TUN_WRITE: Lazy<Box<dyn Fn(&[u8]) + Send + Sync + 'static>> = Lazy::new(|| {
    log::info!("initializing tun-geph");
    let queue_count = std::thread::available_parallelism().unwrap().get();
    let mut dev = Device::new(
        tun::Configuration::default()
            .name("tun-geph")
            .address("100.64.0.1")
            .netmask("255.192.0.0")
            .mtu(1280)
            .up()
            .layer(tun::Layer::L3)
            .queues(queue_count),
    )
    .unwrap();
    // TODO: is this remotely safe??
    for q in 0..queue_count {
        let queue = dev.queue(q).unwrap();
        let queue_fd = queue.as_raw_fd();
        std::thread::Builder::new()
            .name("tun-reader".into())
            .spawn(move || {
                let mut reader = unsafe { std::fs::File::from_raw_fd(queue_fd) };
                // great now we can do our magic
                let mut buf = [0; 2048];
                loop {
                    let n = reader.read(&mut buf).expect("cannot read from tun device");
                    let pkt = &buf[..n];
                    let dest =
                        Ipv4Packet::new(pkt).map(|pkt| INCOMING_MAP.get(&pkt.get_destination()));
                    if let Some(Some(dest)) = dest {
                        if let Err(err) = dest.try_send(Bytes::copy_from_slice(pkt)) {
                            log::trace!("error forwarding packet obtained from tun: {:?}", err);
                        }
                    }
                }
            })
            .unwrap();
    }
    let (send, recv) = smol::channel::bounded::<Vec<u8>>(10000);
    std::thread::Builder::new()
        .name("tun-writer".into())
        .spawn(move || loop {
            let v = recv.recv_blocking().unwrap();
            let _ = dev.write_all(&v);
        })
        .unwrap();
    Box::new(move |b| {
        let _ = send.try_send(b.to_vec());
    })
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
        let first = self.cidr.first();
        let last = self.cidr.last();
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
