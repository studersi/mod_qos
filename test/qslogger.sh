#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`
PFX=[`basename $0`]

TMST=`date '+%a %b %d %H:%M:%S %Y'`
echo "$PFX qslogger"

echo "[$TMST] [error] mod_qos(000): qslogger test message" | ../util/src/qslogger -t mod-qos-logger -f local5
echo "[$TMST] [info] mod_qos(000): qslogger test message" | ../util/src/qslogger -t mod-qos-logger -f local5

sleep 3

if [ `grep -c "mod-qos-logger: \[$TMST\] \[error\] mod_qos(000): qslogger test message" /var/log/local5.error` -ne 1 ]; then
  echo "FAILED"
  tail -2 /var/log/local5.error
  exit 1
fi

if [ `grep -c "mod-qos-logger: \[$TMST\] \[info\] mod_qos(000): qslogger test message" /var/log/local5.info` -ne 1 ]; then
  echo "FAILED"
  tail -2 /var/log/local5.info
  exit 1
fi

exit 0
