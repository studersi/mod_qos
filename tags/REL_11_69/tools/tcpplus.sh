#!/bin/sh

# disable IPv4 routing
echo "0" > /proc/sys/net/ipv4/ip_forward
# disable routing triangulation
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
# disableredirects
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
# disable source routed packets
echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route
# disable acceptance of ICMP redirects
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects
# protection from (DOS) attacks
echo "1" > /proc/sys/net/ipv4/tcp_syncookies
# disable responding to ping broadcasts
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo "1" > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

DPORTS="80,443"

# limit the number of new connections (active after reaching the burst limit only)
iptables -A INPUT -p tcp --dport ${DPORTS} -m limit --state NEW --limit 60/minute --limit-burst 250 -j ACCEPT
#iptables -A INPUT -p tcp -m limit --state NEW --limit 60/minute --limit-burst 250 -j ACCEPT

# limit the number of established/concurrent connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 50/second --limit-burst 50 -j ACCEPT

# limit the connections from a single source IP to 100
iptables -A INPUT -p tcp --syn --dport ${DPORTS} -m connlimit --connlimit-above 100 -j REJECT
