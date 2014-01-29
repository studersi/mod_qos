#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# execute tests using config for use cases (using multiple features/parameters)
#

PFX=[`basename $0`]

./ctl.sh stop 2>/dev/null 1>/dev/null
set -u
ulimit -c unlimited

ERRORS=0

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
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UCN_QS_LocRequestLimit2.htt
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UCN_QS_LocRequestLimit3.htt
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UCN_QS_LocKBytesPerSecLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnb 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCount.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnc 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCount2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnd 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCount3.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnd -D ucne 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCount4.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnf 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_EventLimitCount.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnk 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_EventLimitCount2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucng 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_IPConn.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnh 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_EventRequestLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucni 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientSerialize.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnj 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientSerialize2.htt
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UCN_QS_ClientSerialize4.htt
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UCN_QS_ClientSerialize3.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

if [ $ERRORS -ne 0 ]; then
  echo "$PFX test failed with $ERRORS errors"
  exit $ERRORS
fi
echo "$PFX normal end"
exit 0