#!/bin/sh

# $SystemLogRateLimitInterval 2
# $SystemLogRateLimitBurst 50
# $SystemLogRateLimitSeverity 6

# rsyslogd-2177: imuxsock[pid 29156]: begin to drop messages due to rate-limiting

num=200
rate=100
start=`wc -l /var/log/local5.info | awk '{print $1}'`
./qssyslog -f local5 -s info -l 30 -m $num -n $rate
end=`wc -l /var/log/local5.info | awk '{print $1}'`
n=`echo "${end}-${start}" | bc`
echo "received: $n"

start=`wc -l /var/log/local5.info | awk '{print $1}'`
./qssyslog -f local5 -s error -l 30 -m $num -n $rate
end=`wc -l /var/log/local5.info | awk '{print $1}'`
n=`echo "${end}-${start}" | bc`
echo "received: $n"
