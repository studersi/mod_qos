#!/bin/sh

if [ `uname -s` = "Linux" ]; then
  echo "32000"      > /proc/sys/net/core/somaxconn
  echo "32000"      > /proc/sys/net/core/netdev_max_backlog
  echo "4096 61000" > /proc/sys/net/ipv4/ip_local_port_range
  echo "30"         > /proc/sys/net/ipv4/tcp_fin_timeout
  echo "1"          > /proc/sys/net/ipv4/tcp_window_scaling
  #echo "0"          > /proc/sys/net/ipv4/tcp_sack
  #echo "1280"       > /proc/sys/net/ipv4/tcp_max_syn_backlog
  #echo "1800"       > /proc/sys/net/ipv4/tcp_keepalive_time
  echo "0"          > /proc/sys/net/ipv4/tcp_slow_start_after_idle
  ## or add the parameters to /etc/sysctl.conf
  #net.core.somaxconn = 32000
  #net.core.netdev_max_backlog = 32000
  #net.ipv4.ip_local_port_range = 4096 61000
  #net.ipv4.tcp_fin_timeout = 30
  #net.ipv4.tcp_window_scaling = 1
  #net.ipv4.tcp_slow_start_after_idle = 0
fi

if [ `uname -s` = "SunOS" ]; then
  ndd -set /dev/tcp tcp_time_wait_interval 30000
  ndd -set /dev/tcp tcp_slow_start_initial 2
  ndd -set /dev/tcp tcp_xmit_hiwat 32768
  ndd -set /dev/tcp tcp_recv_hiwat 32768
  ndd -set /dev/tcp tcp_rexmit_interval_initial 2000
  ndd -set /dev/tcp tcp_rexmit_interval_max 20000
  ndd -set /dev/tcp tcp_fin_wait_2_flush_interval 67500
  ndd -set /dev/tcp tcp_smallest_anon_port 4096
  ndd -set /dev/tcp tcp_conn_req_max_q 1024
  ndd -set /dev/tcp tcp_conn_req_max_q0 4096
fi
