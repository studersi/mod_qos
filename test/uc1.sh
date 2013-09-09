#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# execute tests using config for single use cases (only one feature enabled)
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

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1a 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocRequestLimitMatch.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1b 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientEventLimitCount.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1c 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_CondLocRequestLimitMatch.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1d 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocRequestLimit.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1e 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientEventBlockCount.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1f 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_EventRequestLimit.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1g 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_RedirectIf.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1h 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ErrorPage.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

exit 0
