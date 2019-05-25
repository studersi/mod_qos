#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-

./ctl.sh stop 2>/dev/null 1>/dev/null
set -e
set -u
ulimit -c unlimited

waitApache() {
  COUNT=0
  while [ $COUNT -lt 20 ]; do
    if [ -f logs/apache.pid ]; then
      COUNT=20
    else
      let COUNT=$COUNT+1
      ./bin/sleep 200
    fi
  done
}

../httpd/httpd -d `pwd` -f conf/dos.conf 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/QS_SrvRequestRate_0.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/dos.conf 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/dos_session.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/dos.conf 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/dos_keepalive.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

cp /dev/null logs/access_dos_qos_log
# performance with loaded mod_qos (mod_proxy)
../httpd/httpd -d `pwd` -f conf/dos.conf 2>/dev/null 1>/dev/null
waitApache
t1=`date '+%s'`
./run.sh -s scripts/dos_perf.htt
t2=`date '+%s'`
./ctl.sh stop 2>/dev/null 1>/dev/null

cp /dev/null logs/access_dos_log
# performance WITHOUT mod_qos
../httpd/httpd -d `pwd` -f conf/dos.conf -D no_qos 2>/dev/null 1>/dev/null
waitApache
t3=`date '+%s'`
./run.sh -s scripts/dos_perf.htt
t4=`date '+%s'`
./ctl.sh stop 2>/dev/null 1>/dev/null

set +e

totalQos=`cat logs/access_dos_qos_log | awk '{print $(NF-7)}' | awk '{total+=$NF} END{print total}'`
total=`cat logs/access_dos_log | awk '{print $(NF-7)}' | awk '{total+=$NF} END{print total}'`
countQos=`wc -l logs/access_dos_qos_log | awk '{print $1}'`
count=`wc -l logs/access_dos_log | awk '{print $1}'`
averageQos=`expr $totalQos / $countQos`
average=`expr $total / $count`

tw=`expr $t2 - $t1`
to=`expr $t4 - $t3`
percent=`echo "$averageQos*100/$average" | bc`
echo " test duration (seconds) with: $tw, without: $to"
echo " average request duration (microseconds) with: $averageQos (${percent}%), without: $average"
if [ $percent -gt 101 ]; then
  echo " dos.sh test was too slow"
  exit 1
fi
sleep 10
exit 0
