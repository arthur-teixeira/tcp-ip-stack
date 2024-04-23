#!/bin/bash

cargo build
sudo setcap cap_net_admin=eip ./target/debug/tcp-ip
sudo ./target/debug/tcp-ip &
pid=$!
sudo ip addr add 192.168.100.1/24 dev tap1
sudo ip link set up dev tap1
wait $pid
