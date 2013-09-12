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
sleep 3
if [ `grep -c "mod-qos-logger: \[$TMST\] \[error\] mod_qos(000): qslogger test message" /var/log/local5.error` -ne 1 ]; then
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
echo "[$TMST] [info] mod_qos(000): qslogger test message" | ../util/src/qslogger -t mod-qos-logger -f local5
sleep 3
if [ `grep -c "mod-qos-logger: \[$TMST\] \[info\] mod_qos(000): qslogger test message" /var/log/local5.info` -ne 1 ]; then
  echo "FAILED 1"
  tail -2 /var/log/local5.info
  exit 1
fi

# two messages, but one is filtered because only messages with the severity ERROR are forwarded
TMST=`date '+%a %b %d %H:%M:%S %Y'`
echo "[$TMST] [info] mod_qos(000): qslogger test message 1" | ../util/src/qslogger -t mod-qos-logger -f local5 -l INFO
echo "[$TMST] [info] mod_qos(000): qslogger test message 2" | ../util/src/qslogger -t mod-qos-logger -f local5 -l ERROR
sleep 3
if [ `grep -c "mod-qos-logger: \[$TMST\] \[info\] mod_qos(000): qslogger test message" /var/log/local5.info` -ne 1 ]; then
  echo "FAILED 2"
  tail -2 /var/log/local5.info
  exit 1
fi

# can't determine severity (and log notice and higher only but second message has default 'debug')
TMST=`date '+%a %b %d %H:%M:%S %Y'`
echo "[$TMST] mod_qos(000): qslogger test message 1" | ../util/src/qslogger -t mod-qos-logger -f local5
echo "[$TMST] mod_qos(000): qslogger test message 2" | ../util/src/qslogger -t mod-qos-logger -f local5 -d DEBUG
sleep 3
if [ `grep -c "mod-qos-logger: \[$TMST\] mod_qos(000): qslogger test message" /var/log/local5.info` -ne 1 ]; then
  echo "FAILED 3"
  tail -2 /var/log/local5.info
  exit 1
fi

TOT2=`wc -l /var/log/local5.* | tail -1 | awk '{print $1}'`
TOT=`expr $TOT2 - $TOT1`
if [ $TOT -ne 5 ]; then
  echo "FAILED wrong number of new messages in log"
  exit 1
fi

echo "$PFX OK"
exit 0
