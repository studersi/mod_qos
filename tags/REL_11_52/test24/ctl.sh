#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header$
#
# Simple start/stop script (for test purposes only).
#
# See http://mod-qos.sourceforge.net/ for further
# details about mod_qos.
#

cd `dirname $0`

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
export LD_LIBRARY_PATH

echo "[`date '+%a %b %d %H:%M:%S.000000 %Y'`] [notice] -- QS ctl.sh $1 --" >>  logs/error_log

COMMAND=$1
shift
ADDARGS=$@
case "$COMMAND" in
  start)
	ulimit -c unlimited
	if [ "$ADDARGS" = "" ]; then
	  ../httpd/httpd -d `pwd`
	else
	  ../httpd/httpd -d `pwd` $ADDARGS
	fi
	INST="apache"
	for E in $INST; do
	  COUNT=0
	  while [ $COUNT -lt 20 ]; do
	    if [ -f logs/${E}.pid ]; then
	      COUNT=20
	    else
	      let COUNT=$COUNT+1
	      ../test/bin/sleep 500
	    fi
	  done
	done
	../test/bin/sleep 500
	echo "proxy `cat logs/apache.pid`"
	;;
  stop)
	INST="apache"
	for E in $INST; do
	  APID=""
	  if [ -f logs/${E}.pid ]; then
	    APID=`cat logs/${E}.pid`
	    echo "kill $E $APID"
	    kill $APID
            sleep 1
	  fi
	done
	for E in $INST; do
	  COUNTER=0
	  while [ $COUNTER -lt 30 ]; do
	    if [ ! -f logs/${E}.pid ]; then
	      COUNTER=30
	    else
	      ../test/bin/sleep 500
	    fi
	    COUNTER=`expr $COUNTER + 1`
	  done
	done
	../test/bin/sleep 1500
	waitAgain=0
	for epid in `ps -ef | grep "mod-qos/httpd/.libs" | grep -v grep | awk '{print $2}'`; do
	  echo "> kill $epid"
	  kill $epid
	  waitAgain=1
        done
	if [ $waitAgain -eq 1 ]; then
	  sleep 2
          for epid in `ps -ef | grep "mod-qos/httpd/.libs" | grep -v grep | awk '{print $2}'`; do
            echo ">> kill $epid"
            kill -9 $epid
          done
	fi
	;;
  graceful)
	if [ -f logs/apache.pid ]; then
	  echo "sigusr1 proxy `cat logs/apache.pid`"
	  touch logs/apache.pid.graceful
	  kill -USR1 `cat logs/apache.pid`
	  COUNTER=0
	  while [ $COUNTER -lt 4 ]; do
	    NEWER=`find logs/apache.pid -newer logs/apache.pid.graceful`
	    if [ "$NEWER" = "logs/apache.pid" ]; then
	      COUNTER=10
	    else
	      ../test/bin/sleep 500
	    fi
	    COUNTER=`expr $COUNTER + 1`
	  done
	  if [ $COUNTER -eq 4 ]; then
	    echo -e "slow graceful restart \c" 1>&2
	  fi
	  rm logs/apache.pid.graceful
	fi
	;;
  restart)
	$0 stop
        $0 start $ADDARGS
        sleep 2
esac

exit 0
