#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-

./ctl.sh stop 2>/dev/null 1>/dev/null
set -e
set -u
ulimit -c unlimited

../httpd/httpd -d `pwd` -f conf/dos.conf 2>/dev/null 1>/dev/null
sleep 2
./run.sh -s scripts/QS_SrvRequestRate_0.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/dos.conf 2>/dev/null 1>/dev/null
sleep 2
./run.sh -s scripts/dos_session.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/dos.conf 2>/dev/null 1>/dev/null
sleep 2
./run.sh -s scripts/dos_keepalive.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

