#!/bin/sh

HTTEST=${ENV_HTTEST-/usr/local/bin/httest}
RC=0
START=`date '+%s'`
if [ "$1" = "-s" -o "$1" = "-se" ]; then
    LOG=`basename $2`
    echo "run (`date '+%a %b %d %H:%M:%S %Y'`) $2\t\c"
    if [ `expr length $2` -lt 38 ]; then
	echo "\t\c"
    fi
    $HTTEST $2 2>&1 > .${LOG}.log
    RC=$?
    if [ $RC -ne 0 ]; then
	echo "FAILED"
	tail -30 .${LOG}.log
	echo "\nsee `pwd`/.${LOG}.log for more details"
    else
	END=`date '+%s'`
	DIFF=`expr $END - $START`
	echo "OK ($DIFF)"
	rm .${LOG}.log
    fi
else
    $HTTEST $@
    RC=$?
fi
exit $RC