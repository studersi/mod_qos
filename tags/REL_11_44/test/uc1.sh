#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# execute tests using config for single use cases (only one feature enabled)
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

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1a 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocRequestLimitMatch.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1b 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientEventLimitCount.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1bb 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientEventLimitCountbb.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1bb -D uc1bbE 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientEventLimitCountbbE.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1bbb 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientEventLimitCountbbb.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1c 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_CondLocRequestLimitMatch.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1d 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocRequestLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1e 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientEventBlockCount.htt
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UC1_QS_ClientEventBlockCount2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1f 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_EventRequestLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1g 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_RedirectIf.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1g307 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_RedirectIf307.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1h 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ErrorPage.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1i 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocRequestPerSecLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1j 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_EventLimitCount.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1k 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_Milestone.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1ktime 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_Milestone3.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1k -D logonly 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_Milestone2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1l 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1l2 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_csv.htt
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch0.htt
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1l2 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch4.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1l5 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch5.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

./sleep.sh

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1l6 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch6.htt
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch7.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1l7 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch8.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1m 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConn.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1m -D logonly 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConn2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1n 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConnClose.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1o 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_EventPerSecLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1count 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_c_EventLimitCount.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1p 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_CondClientEventLimitCount.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1p -D uc1q 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_CondClientEventLimitCount2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1pp 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_CondClientEventLimitCountpp.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1r 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_UserTrackingCookieName.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1s 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_UserTrackingCookieName.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1ss 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_UserTrackingCookieNameS.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1sss 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_UserTrackingCookieNameDomain.htt
ERRORS=`expr $ERRORS + $?`

./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1ssss 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_UserTrackingCookieNameDomainS.htt
ERRORS=`expr $ERRORS + $?`

./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1t 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_UserTrackingCookieName1.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1u 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMinDataRate.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1uu 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMinDataRateS.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1v 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMinDataRate2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1w 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientSerialize.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1WW 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvSerializeTMO.htt
ERRORS=`expr $ERRORS + $?`
./run.sh -s scripts/UC1_QS_SrvSerialize.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1WWTMO 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvSerializeShortTMO.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null


../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1WWV 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvSerializeV.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1x 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientGeoCountryDB.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1ip2location 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientGeoCountryDBCN.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1x1 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientGeoCountryPriv.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1x2 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientGeoCountryPriv2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1y 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_PermitUri.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1y -D logonly 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_PermitUri2.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D v6 -D uc1v6c 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConnPerIP.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null
./sleep.sh; sleep 3
../httpd/httpd -d `pwd` -f conf/uc1.conf -D v6 -D uc1b 2>/dev/null 1>/dev/null
waitApache
sleep 3
./run.sh -s scripts/UC1_QS_ClientEventLimitCount_v6.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D v6 -D uc1vssl 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConnPerIPSSL.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1ex 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConnPerIPEX.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1ex2 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_SrvMaxConnPerIPEX.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D net 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_net.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D v6 -D uc1w 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientSerialize_v6.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D v6 -D uc1e 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientEventBlockCount_v6.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1z 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_ClientLowPrio.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1z 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_VipIPUser.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1KK 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_MaxKeepAliveRequests.htt
ERRORS=`expr $ERRORS + $?`
sleep 1
./run.sh -s scripts/UC1_QS_KeepAliveTimeout.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

./sleep.sh
sleep 3
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1status 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_Status.htt
RC=$?
if [ $RC -ne 0 ]; then
    tail -2 logs/error_log
fi
ERRORS=`expr $ERRORS + $RC`
./ctl.sh stop 2>/dev/null 1>/dev/null
sleep 1

sleep 3
../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1status -D uc1z -D status 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_QS_Status_2.htt
RC=$?
if [ $RC -ne 0 ]; then
    tail -2 logs/error_log
fi
ERRORS=`expr $ERRORS + $RC`
./ctl.sh stop 2>/dev/null 1>/dev/null
sleep 1

../httpd/httpd -d `pwd` -f conf/uc1.conf -D viewer -D globalmaxconn 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UC1_globalmaxconn.htt
RC=$?
if [ $RC -ne 0 ]; then
    tail -2 logs/error_log
fi
ERRORS=`expr $ERRORS + $RC`
./ctl.sh stop 2>/dev/null 1>/dev/null


if [ $ERRORS -ne 0 ]; then
  echo "$PFX test failed with $ERRORS errors"
  exit $ERRORS
fi
echo "$PFX normal end"
exit 0
