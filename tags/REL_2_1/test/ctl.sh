#!/bin/sh

COMMAND=$1
case "$COMMAND" in
  start)
         ulimit -c unlimited
	 ../httpd/httpd -d `pwd`
	 ../httpd/httpd -d `pwd` -f appl_conf/httpd.conf
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
esac

exit 0
