#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`

if [ `ps -ef | grep -v grep | grep -c "tee test.log"` -eq 0 ]; then
  $0 | tee test.log
  exit $?
fi

ulimit -c unlimited
./generate.sh
. ./ports

ERRORS=0
WARNINGS=0

# delete the access log file since it is used to generate permit rules
./ctl.sh stop > /dev/null
sleep 1
IPCS=`ipcs | wc -l`
rm -f logs/*

echo "start (`date '+%a %b %d %H:%M:%S %Y'`)"
./ctl.sh start > /dev/null

for E in `ls scripts/*.htt`; do
  ./run.sh -s $E
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $E"
  fi
done

./ctl.sh stop > /dev/null
echo "end (`date '+%a %b %d %H:%M:%S %Y'`)"

if [ $WARNINGS -ne 0 ]; then
    echo "ERROR: got $WARNINGS warnings and $ERRORS errors"
    exit 1
fi

if [ $ERRORS -ne 0 ]; then
    echo "ERROR: end with $ERRORS errors"
    exit 1
fi

echo "normal end"
exit 0

