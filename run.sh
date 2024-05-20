#!/bin/bash

cargo build
sudo setcap cap_net_admin=eip ./target/debug/tcp-ip
./target/debug/tcp-ip &
pid=$!
sudo ip addr add 192.168.100.1/24 dev tap1
sudo ip link set up dev tap1
sudo ip route add 10.0.0.7 dev tap1
trap "kill $pid" INT TERM
wait $pid
