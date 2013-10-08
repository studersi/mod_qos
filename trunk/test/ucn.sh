#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# execute tests using config for use cases (using multiple features/parameters)
#

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

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucna 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_LocRequestLimit.htt
./run.sh -s scripts/UCN_QS_LocRequestLimit2.htt
./run.sh -s scripts/UCN_QS_LocRequestLimit3.htt
./run.sh -s scripts/UCN_QS_LocKBytesPerSecLimit.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnb 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCount.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnc 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCount2.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnd 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCount3.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

exit 0
