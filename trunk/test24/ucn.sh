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

../httpd/httpd -d `pwd` -f conf/ucn.conf -D ucna 2>/dev/null 1>/dev/null
waitApache
./run.sh -s scripts/UCN_QS_LocRequestLimit.htt
ERRORS=`expr $ERRORS + $?`
./ctl.sh stop 2>/dev/null 1>/dev/null

if [ $ERRORS -ne 0 ]; then
  echo "$PFX test failed with $ERRORS errors"
  exit $ERRORS
fi

echo "$PFX normal end"
exit 0
