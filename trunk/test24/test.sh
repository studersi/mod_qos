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

if [ `../httpd/httpd -l | grep -c worker.c` -eq 1 ]; then
    for E in `ls scripts/*WORKER.htt | sort`; do
	./run.sh -seT $E
	if [ $? -ne 0 ]; then
	    ERRORS=`expr $ERRORS + 1`
	    echo "FAILED $E"
	fi
	sleep 2
    done
fi
if [ `../httpd/httpd -l | grep -c event.c` -eq 1 ]; then
    for E in `ls scripts/*EVENT.htt | sort`; do
	./run.sh -seT $E
	if [ $? -ne 0 ]; then
	    ERRORS=`expr $ERRORS + 1`
	    echo "FAILED $E"
	fi
	sleep 2
    done
fi

for E in `ls scripts/*.htt | grep -v -e "dos.htt" -e "WORKER.htt" -e "EVENT.htt" -e "_h2" -e "UCN_" | sort`; do
  ./run.sh -seT $E
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $E"
  fi
  sleep 2
done

./ctl.sh stop > /dev/null

./ctl.sh start -D h2 > /dev/null

# 
# ~/projects/openssl-1.0.2g$ ./config --prefix=$HOME/openssl -fPIC no-gost no-shared no-zlib
# ~/projects/curl-7.45.0$ LIBS="-ldl" ./configure --with-nghttp2 --with-ssl=$HOME/openssl/ --libdir=$HOME/openssl/lib
# 
for E in `ls scripts/*.htt | grep "_h2" | sort`; do
  ./run.sh -seT $E
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $E"
  fi
  sleep 2
done

./ucn.sh
RC=$?
ERRORS=`expr $ERRORS + $RC`

./dos.sh
RC=$?
ERRORS=`expr $ERRORS + $RC`

./ctl.sh stop > /dev/null
echo "end (`date '+%a %b %d %H:%M:%S %Y'`)"

CFS=`find . -name "*core*"`
if [ -n "$CFS" ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED found core file"
fi

if [ `grep -c -e "exit signal" -e AH00051 -e AH00052 logs/error_log` -gt 0 ]; then
    WARNINGS=`expr $WARNINGS + 1`
    echo "WARNING: found 'exit signal' message"
fi

if [ `grep -c "unclean child exit" logs/error_log` -gt 0 ]; then
    WARNINGS=`expr $WARNINGS + 1`
    grep "unclean child exit" logs/error_log | tail
    echo "WARNING: found 035/036 error message"
fi    

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

