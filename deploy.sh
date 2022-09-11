#!/bin/bash
cargo build --release --target x86_64-unknown-linux-musl --manifest-path ./Cargo.toml

export HOSTS="us-pdx-01.exits.geph.io nl-ams-01.exits.geph.io jp-tyo-01.exits.geph.io 139.99.8.18 ca-mtl-02.exits.geph.io tw-rmq-01.exits.geph.io us-dal-01.exits.geph.io ch-zrh-01.exits.geph.io us-sfo-02.exits.geph.io"

for host in $HOSTS          
do                                         
rsync -avz --progress ./target/x86_64-unknown-linux-musl/release/geph4-exit root@$host:/usr/local/bin/ &
done; wait;

for host in $HOSTS
do                             
echo "restarting $host..."
ssh root@$host service geph4-exit restart
#sleep 60
done; wait;

