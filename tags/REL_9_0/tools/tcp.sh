#!/bin/sh

echo "32000"      > /proc/sys/net/core/somaxconn
echo "32000"      > /proc/sys/net/core/netdev_max_backlog
echo "4096 61000" > /proc/sys/net/ipv4/ip_local_port_range
echo "30"         > /proc/sys/net/ipv4/tcp_fin_timeout
