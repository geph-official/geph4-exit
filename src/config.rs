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

    /// A mapping between an ASN and proxy servers to redirect all port 443 TCP connections to. This must be the address of some kind of "sniproxy" instance. Generally used to specially redirect e.g. Google traffic.
    ///
    /// TODO: Will be replaced once Geph gets proper IPv6 support!
    #[getset(get = "pub")]
    asn_sniproxies: Option<BTreeMap<String, SocketAddr>>,

    /// Where to listen to for incoming sosistab connections.
    #[getset(get = "pub")]
    #[serde(default = "sosistab_listen_default")]
    sosistab_listen: String,

    /// Configuration options for "official" servers connected to a binder
    #[getset(get = "pub")]
    official: Option<OfficialConfig>,

    /// Whether or not to get ip address from external service
    #[getset(get_copy = "pub")]
    #[serde(default)]
    disable_reflective_ip_detection: bool,
}

fn sosistab_listen_default() -> String {
    "[::0]:19831".into()
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

fn binder_http_default() -> String {
    "https://binder-v4.geph.io".into()
}

fn binder_master_pk_default() -> String {
    "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b".into()
}

fn binder_statsd_address_default() -> SocketAddr {
    "172.105.28.221:8125".parse().unwrap()
}
