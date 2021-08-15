use std::{
    io::BufReader,
    net::{IpAddr, Ipv4Addr},
};

use cached::proc_macro::cached;
use flate2::bufread::GzDecoder;
use once_cell::sync::Lazy;
use rangemap::RangeMap;

static IPV4_MAP: Lazy<RangeMap<Ipv4Addr, u32>> = Lazy::new(|| {
    use std::io::prelude::*;
    let resp = ureq::get("https://iptoasn.com/data/ip2asn-v4.tsv.gz").call();
    if resp.status() != 200 {
        panic!("iptoasn.com failed")
    }
    let reader = resp.into_reader();
    let reader = BufReader::new(GzDecoder::new(BufReader::new(reader)));
    let mut toret = RangeMap::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.expect("I/O error while downloading ASN database");
        if idx % 1000 == 0 {
            log::debug!("loading line {} of ASN database...", idx);
        }
        let elems: Vec<&str> = line.split_ascii_whitespace().collect();
        if elems.len() < 3 {
            log::warn!("skipping line in ASN database: {}", line)
        } else {
            let start: Ipv4Addr = elems[0].parse().unwrap();
            let end: Ipv4Addr = next_ip(elems[1].parse().unwrap());
            let asn: u32 = elems[2].parse().unwrap();
            if end > start {
                toret.insert(start..end, asn);
            }
        }
    }
    toret
});

/// the "next" IP address
pub fn next_ip(ip: Ipv4Addr) -> Ipv4Addr {
    (u32::from_be_bytes(ip.octets()).saturating_add(1)).into()
}

/// Returns the ASN of this IP address, or zero if unable to.
#[cached(size = 65536)]
pub fn get_asn(addr: IpAddr) -> u32 {
    match addr {
        IpAddr::V4(addr) => IPV4_MAP.get(&addr).cloned().unwrap_or_default(),
        _ => 0,
    }
}
