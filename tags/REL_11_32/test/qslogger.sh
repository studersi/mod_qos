#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# /etc/rsyslog.conf:
# local5.emerg /var/log/local5.emegr
# local5.error /var/log/local5.error
# local5.info  /var/log/local5.info
#

cd `dirname $0`
PFX=[`basename $0`]

echo "$PFX qslogger"

TOT1=`wc -l /var/log/local5.* | tail -1 | awk '{print $1}'`
# one message to the local5.error file
TMST=`date '+%a %b %d %H:%M:%S %Y'`
echo "[$TMST] [error] mod_qos(000): qslogger test message emerg" | ../util/src/qslogger -t mod-qos-logger -f local5
sleep 2
echo "$PFX $TMST"
if [ `grep -c "mod-qos-logger: \[$TMST\] \[error\] mod_qos(000): qslogger test message emerg" /var/log/local5.error` -ne 1 ]; then
  echo "FAILED 0"
  tail -2 /var/log/local5.error
  exit 1
fi
if [ `tail -2 /var/log/local5.emegr | grep -c "qslogger test"` -gt 0 ]; then
  echo "FAILED, invalid severity"
  tail -2 /var/log/local5.emegr
  exit 1
fi

# one message to the local5.info file
TMST=`date '+%a %b %d %H:%M:%S %Y'`
echo "[$TMST] [info] mod_qos(000): qslogger test message 0" | ../util/src/qslogger -t mod-qos-logger -f local5
sleep 2
if [ `grep -c "mod-qos-logger: \[$TMST\] \[info\] mod_qos(000): qslogger test message 0" /var/log/local5.info` -ne 1 ]; then
  echo "FAILED 1"
  tail -2 /var/log/local5.info
  exit 1
fi

# two messages, but one is filtered because only messages with the severity ERROR are forwarded
TMST=`date '+%a %b %d %H:%M:%S %Y'`
echo "[$TMST] [info] mod_qos(000): qslogger test message 1" | ../util/src/qslogger -t mod-qos-logger -f local5 -l INFO
echo "[$TMST] [info] mod_qos(000): qslogger test message 2" | ../util/src/qslogger -t mod-qos-logger -f local5 -l ERROR
sleep 2
if [ `grep -c "mod-qos-logger: \[$TMST\] \[info\] mod_qos(000): qslogger test message 1" /var/log/local5.info` -ne 1 ]; then
  echo "FAILED 2"
  tail -2 /var/log/local5.info
  exit 1
fi

# can't determine severity (and log notice and higher only but second message has default 'debug')
TMST=`date '+%a %b %d %H:%M:%S %Y'`
echo "[$TMST] mod_qos(000): qslogger test message 3" | ../util/src/qslogger -t mod-qos-logger -f local5
echo "[$TMST] mod_qos(000): qslogger test message 4" | ../util/src/qslogger -t mod-qos-logger -f local5 -d DEBUG
sleep 2
if [ `grep -c "mod-qos-logger: \[$TMST\] mod_qos(000): qslogger test message 3" /var/log/local5.info` -ne 1 ]; then
  echo "FAILED 3"
  tail -2 /var/log/local5.info
  exit 1
fi

# special format, info message
echo "2013 09 10 15:37:39.111 data4web IW5SuGus 1683.4733680637248.c13fe18-44c0-a1f44-44408177d24-0445b2ed 6-INFO : UsersMiniMeRoleFilter: pass through (no role required): initial access for '/mod-qos/mappings/plugins/macrobrowser/browse-macros.action" | ../util/src/qslogger -t apache/server -f local5 -l info -d debug -r "^[a-zA-Z0-9\\.: -]+ [0-9]-([A-Z_]{4,9}).*"
sleep 2
if [ `tail -1 /var/log/local5.info | grep -c "2013 09 10 15:37:39.111 data4web IW5SuGus"` -ne 1 ]; then
  echo "FAILED 4"
  tail -2 /var/log/local5.info
  exit 1
fi
echo "2013 09 10 15:37:39.572 data4web MyProxy 16d32.433248.c3e18-31c0-a1f33-1332xd24-0c2d 6-INFO : reqF=\"GET /mod-qos/mappings/plugins/macrobrowser/browse-macros.action HTTP/1.1\" reqDecF=<NULL> ipF=172.11.25.24 sCF=200 bSF=4840 dTF=42 reqB=\"GET /mod-qos/mappings/plugins/macrobrowser/browse-macros.action HTTP/1.1\" adrB=mysss.ch:80 ipB=172.12.0.34 sCB=200 dTB=49 dTcB=0 dTsB=0 dTr1B=195 dTr2B=24 invS=SSSe0 cR=3 usrID=nobody12 Event=<NULL> clID=3VLjnCUs= cookie=diEmERgoY- sslID=d24-0005b2ed" | ../util/src/qslogger -t apache/server -f local5 -l info -d debug -r "^[a-zA-Z0-9\\.: -]+ [0-9]-([A-Z_]{4,9}).*"
sleep 2
if [ `tail -1 /var/log/local5.info | grep -c "apache/server: 2013 09 10 15:37:39.572 data4web MyProxy"` -ne 1 ]; then
  echo "FAILED 5"
  tail -2 /var/log/local5.info
  exit 1
fi
echo "2010 12 04 20:46:45.118 dispatch   IWWWauthCo 07148.4046314384 3-ERROR :  AuthsessClient_1_0::execute: no valid" | ../util/src/qslogger -t apache/server -f local5 -l info -d debug -r "^[a-zA-Z0-9\\.: -]+ [0-9]-([A-Z_]{4,9}).*"
sleep 2
if [ `tail -1 /var/log/local5.info | grep -c "apache/server: 2010 12 04 20:46:45.118 dispatch   IWWWauthCo"` -ne 1 ]; then
  echo "FAILED 6"
  tail -2 /var/log/local5.info
  exit 1
fi
if [ `tail -1 /var/log/local5.error | grep -c "apache/server: 2010 12 04 20:46:45.118 dispatch   IWWWauthCo"` -ne 1 ]; then
  echo "FAILED 7"
  tail -2 /var/log/local5.error
  exit 1
fi


#
# total 9 new entries:
#
# /var/log/local5.emerg
# -nothing-
#
# /var/log/local5.error 
# mod-qos-logger: [error] mod_qos(000): qslogger test message emerg
# apache/server: 2010 12 04 20:46:45.118 dispatch   IWWWauthCo
# 
# /var/log/local5.info
# mod-qos-logger: [error] mod_qos(000): qslogger test message emerg
# mod-qos-logger: [info] mod_qos(000): qslogger test message 0
# mod-qos-logger: [info] mod_qos(000): qslogger test message 1
# mod-qos-logger: mod_qos(000): qslogger test message 3
# apache/server: 2013 09 10 15:37:39.111 data4web IW5SuGus
# apache/server: 2013 09 10 15:37:39.572 data4web MyProxy
# apache/server: 2010 12 04 20:46:45.118 dispatch   IWWWauthCo
#
TOT2=`wc -l /var/log/local5.* | tail -1 | awk '{print $1}'`
TOT=`expr $TOT2 - $TOT1`
if [ $TOT -ne 9 ]; then
  echo "FAILED wrong number of new messages in log"
  exit 1
fi


echo "[$TMST] [error] mod_qos(001): qslogger test message emerg" | ../util/src/qslogger -x "message prefix: " -t mod-qos-logger -f local5
sleep 1
if [ `tail -1 /var/log/local5.error | egrep -c "mod-qos-logger: message prefix: \[$TMST\] \[error\] mod_qos\(001\): qslogger test message emerg"` -ne 1 ]; then
  echo "FAILED, missing prefix"
  tail -2 /var/log/local5.error
  exit 1
fi


echo "$PFX OK"
exit 0
