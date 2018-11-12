#!/bin/sh

RC=0
START=`date '+%s'`
if [ "$1" = "-s" -o "$1" = "-se" ]; then
    LOG=`basename $2`
    echo "run (`date '+%a %b %d %H:%M:%S %Y'`) $2\t\c"
    if [ `expr length $2` -lt 38 ]; then
	echo "\t\c"
    fi
    while [ 1 ]; do
	/usr/local/bin//httest $2 2>&1 > .${LOG}.log
	RC=$?
	if [ $RC -ne 0 ]; then
	    echo "FAILED"
	    exit $RC
	else
	    END=`date '+%s'`
	    DIFF=`expr $END - $START`
	    echo "OK ($DIFF)"
	    rm .${LOG}.log
	fi
    done
else
    /usr/local/bin/httest $@
fi
exit $RC
