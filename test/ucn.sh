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
  sleep 2
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

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucna -D ucnavip 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_VipHeaderName.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnb 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCount.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnbhash 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventLimitCountHash.htt
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

sleep 10

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnh 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_EventRequestLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

sleep 10

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucni 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientSerialize.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnip 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_SrvSerialize.htt
ERRORS=`expr $ERRORS + $?`
sleep 1
./run.sh -s scripts/UCN_QS_SrvSerialize2.htt
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

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnl 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_Milestone.htt
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UCN_QS_CondClientEventLimitCount.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

sleep 1
../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnm 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_LocRequestLimitMaxClients.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

sleep 1
../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucno 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_CondClientEventLimitCount_adm.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnp 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_RedrirectIf.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnq 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_SetReqHeader.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnr 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_console.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucns 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_DenyEvent.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucns -D logonly 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_DenyEvent2.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnt 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventBlockExcludeIP.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnt -D ucnt2 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventBlockExcludeIP2.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnt -D ucnt3 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventBlock3.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucnt4 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_ClientEventBlock4.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucncust01 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_Cust01.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

./run.sh -s scripts/ucnu.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucncc 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_cc.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/ucn.conf -D fleet 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_fleet.htt
ERRORS=`expr $ERRORS + $?`
sleep 2
./ctl.sh stop 2>/dev/null 1>/dev/null

if [ $ERRORS -ne 0 ]; then
  echo "$PFX test failed with $ERRORS errors"
  exit $ERRORS
fi
echo "$PFX normal end"
exit 0

