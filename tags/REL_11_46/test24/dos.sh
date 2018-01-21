#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-

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

for E in `ls scripts/*dos.htt | sort`; do
  waitApache
  ./run.sh -seT $E
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $E"
  fi
  ./ctl.sh stop 2>/dev/null 1>/dev/null
  sleep 2
done

if [ $ERRORS -ne 0 ]; then
  echo "$PFX test failed with $ERRORS errors"
  exit $ERRORS
fi

echo "$PFX normal end"
exit 0
