#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/test/ctl.sh,v 2.10 2010-02-05 21:34:31 pbuchbinder Exp $
#
# Simple start/stop script (for test purposes only).
#
# See http://sourceforge.net/projects/mod-qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007-2010 Pascal Buchbinder
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#

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
	INST="apache apache1"
	for E in $INST; do
	  COUNT=0
	  while [ $COUNT -lt 10 ]; do
	    if [ -f logs/${E}.pid ]; then
	      COUNT=10
	    else
	      let COUNT=$COUNT+1
	      sleep 1
	    fi
	  done
	done
	echo "proxy `cat logs/apache.pid`"
	echo "application `cat logs/apache1.pid`"
	;;
  stop)
	INST="apache apache1"
	for E in $INST; do
	  if [ -f logs/${E}.pid ]; then
	    echo "kill $E `cat logs/${E}.pid`"
	    kill `cat logs/${E}.pid`
	  fi
	done
	for E in $INST; do
	  COUNTER=0
	  while [ $COUNTER -lt 10 ]; do
	    if [ ! -f logs/${E}.pid ]; then
	      COUNTER=10
	    else
	      sleep 1
	    fi
	    COUNTER=`expr $COUNTER + 1`
	  done
	done
	;;
  graceful)
	if [ -f logs/apache.pid ]; then
	  echo "sigusr1 proxy `cat logs/apache.pid`"
	  touch logs/apache.pid.graceful
	  kill -USR1 `cat logs/apache.pid`
	  COUNTER=0
	  while [ $COUNTER -lt 10 ]; do
	    NEWER=`find logs/apache.pid -newer logs/apache.pid.graceful`
	    if [ "$NEWER" = "logs/apache.pid" ]; then
	      COUNTER=10
	    else
	      sleep 1
	    fi
	    COUNTER=`expr $COUNTER + 1`
	  done
	  rm logs/apache.pid.graceful
	fi
	;;
  restart)
	$0 stop
        $0 start $ADDARGS
esac

exit 0
