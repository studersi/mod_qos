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

# performance with loaded mod_qos (mod_proxy)
../httpd/httpd -d `pwd` -f conf/dos.conf 2>/dev/null 1>/dev/null
sleep 2
t1=`date '+%s'`
./run.sh -s scripts/dos_perf.htt
t2=`date '+%s'`
./ctl.sh stop 2>/dev/null 1>/dev/null

# performance WITHOUT mod_qos
../httpd/httpd -d `pwd` -f conf/dos.conf -D no_qos 2>/dev/null 1>/dev/null
sleep 2
t3=`date '+%s'`
./run.sh -s scripts/dos_perf.htt
t4=`date '+%s'`
./ctl.sh stop 2>/dev/null 1>/dev/null

set +e
tw=`expr $t2 - $t1`
to=`expr $t4 - $t3`
echo " with: $tw, without: $to"
dif=`expr $tw - $to`
# up to 1% slower (incl rounding) is still okay (since the server
# has not really anything else to do)
if [ $dif -gt 2 ]; then
  echo " dos.sh test was too slow"
  exit 1
fi
sleep 10
exit 0
