#!/bin/bash
cargo build --release --target x86_64-unknown-linux-musl --manifest-path ~/GEPH4/geph4-exit/Cargo.toml

for host in us-pdx-01.exits.geph.io nl-ams-01.exits.geph.io sosistab-jp-test.labooyah.be sg-sgp-03.exits.geph.io ca-mtl-02.exits.geph.io tw-rmq-01.exits.geph.io us-dal-01.exits.geph.io          
do                                         
rsync -avz --progress ~/GEPH4/geph4-exit/target/x86_64-unknown-linux-musl/release/geph4-exit root@$host:/usr/local/bin/ &
done; wait;

for host in us-pdx-01.exits.geph.io sosistab-jp-test.labooyah.be sg-sgp-03.exits.geph.io tw-rmq-01.exits.geph.io nl-ams-01.exits.geph.io ca-mtl-02.exits.geph.io us-dal-01.exits.geph.io
do                             
echo "restarting $host..."
ssh root@$host service geph4-exit restart
sleep 10
done; wait;

