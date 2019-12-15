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
    fi
    ./bin/sleep 200
  done
  sleep 2
}

echo "$PFX start"
../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucna 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_QS_LocRequestLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnb -D qtest 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_QS_EventRequestLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D limit2block 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_limit2block_1.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D limit2block -D qtest 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_block403.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D limit2block -D usertracking 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_limit2blockCookie.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null


../httpd/httpd -d `pwd` -f conf/ucn.conf -D limit2level 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_limit2level.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D limit2levelnext 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_limit2levelnext.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D e1 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_e1.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D e2 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_e2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ssi 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_ssi.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D serialize 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_serialize.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D serializeReq -D qtest 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_serializeReq.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D hash -D qtest 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_clientIpFromHeader.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D minDataRateSimple 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_QS_SrvMinDataRate.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D minDataRateSimpleDual 2>/dev/null 1>/dev/null
waitApache
./run.sh -seT scripts/UCN_QS_SrvMinDataRateD.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null


if [ $ERRORS -ne 0 ]; then
  echo "$PFX test failed with $ERRORS errors"
  exit $ERRORS
fi

echo "$PFX normal end"
exit 0
