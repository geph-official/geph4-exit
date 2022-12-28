use cidr_utils::cidr::Ipv6Cidr;
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

/// TOML-serializable configuration file for geph4-exit
#[derive(CopyGetters, Getters, Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    /// Where to place the secret key. On first startup, a key will be written to this location
    #[getset(get = "pub")]
    #[serde(default = "secret_key_default")]
    secret_key: PathBuf,

    /// Where to place the secret key for sosistab2. On first startup, a key will be written to this location
    #[getset(get = "pub")]
    #[serde(default = "secret_sosistab2_key_default")]
    secret_sosistab2_key: PathBuf,

    /// Whether or not to limit the open ports to a "safe" list similar to the default policy of Tor exits. See https://github.com/geph-official/geph4-exit/blob/master/src/lists.rs
    #[getset(get_copy = "pub")]
    #[serde(default)]
    port_whitelist: bool,

    /// Whether or not to anonymize logs.
    #[getset(get_copy = "pub")]
    #[serde(default)]
    anonymize_logs: bool,

    /// Whether or not to spam gzipped sosistab traces to a given file.
    #[getset(get = "pub")]
    #[serde(default)]
    sosistab_trace: Option<PathBuf>,

    /// External interface on which VPN packets should be forwarded. Must be set in order to use VPN mode!
    #[getset(get = "pub")]
    nat_external_iface: Option<String>,

    /// If set, randomizes source IPs of outgoing IPv6 TCP connections by drawing from this IPv6 range
    #[getset(get = "pub")]
    random_ipv6_range: Option<Ipv6Cidr>,

    /// If set, sends IPv6 TCP connections from this interface name
    #[getset(get = "pub")]
    ipv6_interface: Option<String>,

    /// If set, forces all DNS requests to this destination.
    #[getset(get = "pub")]
    force_dns: Option<SocketAddr>,

    /// If set, force-disables TCP termination. This can impact statistics gathering and performance, but may be necessary in resource-constrained environments.
    #[getset(get = "pub")]
    #[serde(default)]
    disable_tcp_termination: bool,

    /// A mapping between an ASN and proxy servers to redirect all port 443 TCP connections to. This must be the address of some kind of "sniproxy" instance. Generally used to specially redirect e.g. Google traffic.
    ///
    /// TODO: Will be replaced once Geph gets proper IPv6 support!
    #[getset(get = "pub")]
    asn_sniproxies: Option<BTreeMap<String, SocketAddr>>,

    /// Speed limit, in KB/s, for each token.
    #[getset(get = "pub")]
    #[serde(default = "all_limit_default")]
    all_limit: u32,

    /// Where to listen to for incoming *direct* sosistab connections.
    #[getset(get = "pub")]
    #[serde(default = "sosistab_listen_default")]
    sosistab_listen: String,

    /// Where to listen to for incoming *direct* sosistab2 connections.
    #[getset(get = "pub")]
    #[serde(default = "sosistab2_listen_default")]
    sosistab2_listen: String,

    /// Configuration options for "official" servers connected to a binder
    #[getset(get = "pub")]
    official: Option<OfficialConfig>,

    /// Limit on the number of outgoing TCP connections. By default, 3000.
    #[getset(get_copy = "pub")]
    #[serde(default = "conn_count_limit_default")]
    conn_count_limit: usize,
}

fn all_limit_default() -> u32 {
    120000
}

fn sosistab_listen_default() -> String {
    "[::0]:19831".into()
}

fn sosistab2_listen_default() -> String {
    "[::0]:17814".into()
}

fn conn_count_limit_default() -> usize {
    3000
}

impl Config {
    /// Redacts a string.
    pub fn redact(&self, t: impl ToString) -> String {
        if self.anonymize_logs() {
            "[REDACTED]".to_string()
        } else {
            t.to_string()
        }
    }
}

/// Config options specific to official servers
#[derive(Getters, Serialize, Deserialize, Clone, Debug)]
pub struct OfficialConfig {
    /// HTTP address of the binder
    #[getset(get = "pub")]
    #[serde(default = "binder_http_default")]
    binder_http: String,

    /// UDP address of the statsd daemon
    #[getset(get = "pub")]
    #[serde(default = "binder_statsd_address_default")]
    statsd_addr: SocketAddr,

    /// x25519 master key of the binder
    #[getset(get = "pub")]
    #[serde(default = "binder_master_pk_default")]
    binder_master_pk: String,

    /// Hostname of this exit.
    #[getset(get = "pub")]
    exit_hostname: String,

    /// Bridge secret.
    #[getset(get = "pub")]
    bridge_secret: String,

    /// Free-user speed limit, in KB/s. If not present, then reject free users altogether.
    #[getset(get = "pub")]
    free_limit: Option<u32>,
}

fn secret_key_default() -> PathBuf {
    "/var/local/geph4-exit.key".into()
}

fn secret_sosistab2_key_default() -> PathBuf {
    "/var/local/geph4-exit-sosis2.key".into()
}

fn binder_http_default() -> String {
    "https://binder-v4.geph.io/next-gen".into()
}

fn binder_master_pk_default() -> String {
    "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b".into()
}

fn binder_statsd_address_default() -> SocketAddr {
    "172.105.28.221:8125".parse().unwrap()
}
