#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`
PFX=[`basename $0`]

echo "$PFX qslogger"

# one message to the local5.error file
TMST=`date '+%a %b %d %H:%M:%S %Y'`
echo "[$TMST] [error] mod_qos(000): qslogger test message" | ../util/src/qslogger -t mod-qos-logger -f local5
sleep 3
if [ `grep -c "mod-qos-logger: \[$TMST\] \[error\] mod_qos(000): qslogger test message" /var/log/local5.error` -ne 1 ]; then
  echo "FAILED 0"
  tail -2 /var/log/local5.error
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

exit 0
