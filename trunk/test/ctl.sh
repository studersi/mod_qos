#!/bin/sh

COMMAND=$1
case "$COMMAND" in
  start)
         ulimit -c unlimited
	 ../httpd/httpd -d `pwd`
	 sleep 1
	 cat logs/apache.pid
	 ;;
  stop)
         echo "kill `cat logs/apache.pid`"
	 kill `cat logs/apache.pid`
	 ;;
esac

exit 0
