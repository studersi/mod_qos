#!/bin/sh

./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D clientSerial 2>/dev/null 1>/dev/null
. ./ports

for counter in `seq 100`; do
    echo "GET /index.html?client=${counter}&delayus=200000 HTTP/1.0\n" | telnet server1 $QS_PORT_BASE
done
sleep 22

./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D srvSerial 2>/dev/null 1>/dev/null
. ./ports

for counter in `seq 100`; do
    echo "GET /index.html?srv=${counter}&delayus=200000 HTTP/1.0\n" | telnet server1 $QS_PORT_BASE
done
sleep 22

./ctl.sh stop 2>/dev/null 1>/dev/null
