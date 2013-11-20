#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# execute tests using config for single use cases (only one feature enabled)
#

PFX=[`basename $0`]
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
./run.sh -s scripts/UC1_QS_ClientEventBlockCount2.htt
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

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1i 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocRequestPerSecLimit.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1j 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_EventLimitCount.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1k 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_Milestone.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1l 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1m 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConn.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1n 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConnClose.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1o 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_EventPerSecLimit.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1p 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_CondClientEventLimitCount.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1p -D uc1q 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_CondClientEventLimitCount2.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1r 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_UserTrackingCookieName.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

echo "$PFX normal end"
exit 0

