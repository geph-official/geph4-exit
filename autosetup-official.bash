#!/bin/bash

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "autosetup.sh must be run as root!"
    exit
fi

set -e


echo "STEP 0: Installing prereqs"
apt-get install -y build-essential git ndppd iptables


echo "STEP 1: Installing Rust / 正在安裝 Rust"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env


echo "STEP 2: Creating config files"
dd of=/etc/geph4-exit.toml << EOF
random_ipv6_range = "$IPV6_RANGE"
ipv6_interface = "$IPV6_INTERFACE"


nat_external_iface = "$MAIN_INTERFACE"
port_whitelist = $PORT_WHITELIST
conn_count_limit = 100000

[official]
exit_hostname = "$EXIT_HOSTNAME"
bridge_secret = "$BRIDGE_SECRET"
free_limit = $FREE_LIMIT

EOF

dd of=/etc/ndppd.conf << EOF
route-ttl 30000

proxy $IPV6_INTERFACE {
    router no
    timeout 500
    ttl 30000

    rule $IPV6_RANGE {
        static
    }
}
EOF

dd of=/etc/sysctl.conf << EOF
net.core.rmem_default=262144
net.core.wmem_default=262144
net.core.rmem_max=262144000
net.core.wmem_max=262144000
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc = fq
net.ipv4.ip_forward=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_reordering=100
net.ipv4.tcp_max_reordering=10000
net.core.somaxconn = 6553600
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.udp_mem = 786432 1048576 26777216
net.ipv6.ip_nonlocal_bind=1
net.ipv4.conf.all.route_localnet=1
EOF
sysctl -p

echo "STEP 3: Cloning geph4-exit repo"
cd /opt/
rm -rfv geph4-exit
git clone https://github.com/geph-official/geph4-exit.git

echo "STEP 4: Creating start script"
dd of=/opt/geph4-exit-start << EOF
#!/bin/sh
export PATH=$PATH:/root/.bin/cargo
rustup update
cd /opt/geph4-exit
git pull
cargo install --path . --locked
export SOSISTAB_NO_OOB=1
geph4-exit --config /etc/geph4-exit.toml
EOF

chmod +x /opt/geph4-exit-start

echo "STEP 5: Creating systemd unit"
sudo dd of=/etc/systemd/system/geph4-exit.service << EOF 
[Unit]
Description=Geph4 exit service.
[Service]
Type=simple
Restart=always
ExecStart=/opt/geph4-exit-start
LimitNOFILE=655360
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl restart ndppd
sudo chmod 644 /etc/systemd/system/geph4-exit.service
sudo systemctl enable geph4-exit
sudo systemctl daemon-reexec
sudo systemctl restart geph4-exit

echo "STEP 6: Waiting for public key..."
journalctl -f -u geph4-exit