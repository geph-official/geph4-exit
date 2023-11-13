

use once_cell::sync::Lazy;

use std::{
    net::{Ipv4Addr},
};

/// my own IP address
pub static MY_PUBLIC_IP: Lazy<Ipv4Addr> = Lazy::new(|| {
    let resp = ureq::get("http://checkip.amazonaws.com").call();
    resp.into_string()
        .expect("cannot get my public IP")
        .trim()
        .parse()
        .expect("got invalid IP address for myself")
});

/// the "next" IP address
pub fn next_ip(ip: Ipv4Addr) -> Ipv4Addr {
    (u32::from_be_bytes(ip.octets()).saturating_add(1)).into()
}
