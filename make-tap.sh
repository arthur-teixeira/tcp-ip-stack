#!/bin/bash

sudo ip tuntap add tap0 mode tap user arthur
sudo ip addr add 69.69.69.69/24 dev tap0
sudo ip link set tap0 up
