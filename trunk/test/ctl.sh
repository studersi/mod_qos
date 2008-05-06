#!/bin/sh

COMMAND=$1
shift
ADDARGS=$@
case "$COMMAND" in
  start)
         ulimit -c unlimited
	 if [ "$ADDARGS" = "" ]; then
	    ../httpd/httpd -d `pwd`
            ../httpd/httpd -d `pwd` -f appl_conf/httpd.conf
	 else
	    ../httpd/httpd -d `pwd` $ADDARGS
            ../httpd/httpd -d `pwd` -f appl_conf/httpd.conf $ADDARGS
	 fi
	 sleep 1
	 echo "proxy `cat logs/apache.pid`"
	 echo "application `cat logs/apache1.pid`"
	 ;;
  stop)
         if [ -f logs/apache.pid ]; then
           echo "kill proxy `cat logs/apache.pid`"
	    kill `cat logs/apache.pid`
         fi
         if [ -f logs/apache1.pid ]; then
           echo "kill application `cat logs/apache1.pid`"
	   kill `cat logs/apache1.pid`
         fi
	 ;;
  graceful)
         if [ -f logs/apache.pid ]; then
           echo "sigusr1 proxy `cat logs/apache.pid`"
	   kill -USR1 `cat logs/apache.pid`
         fi
	 ;;
  restart)
    $0 stop
    sleep 2
    $0 start $ADDARGS
esac

exit 0
