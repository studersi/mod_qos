#!/bin/sh

HTTEST=${ENV_HTTEST-/usr/local/bin/httest}
if [ -n "$2" ]; then
    HTS=`grep "#HTTEST=" $2 | awk -F'=' '{print $2}'`
    if [ -n "$HTS" ]; then
	if [ -x $HTS ]; then
	    HTTEST=$HTS
	else
	    echo "WARNING $HTS does not exist, fallback to $HTTEST"
	fi
    fi
fi
RC=0
START=`date '+%s'`
if [ "$1" = "-s" -o "$1" = "-se" ]; then
    $HTTEST -s -e $2
    RC=$?
#    LOG=`basename $2`
#    echo "run (`date '+%a %b %d %H:%M:%S %Y'`) $2\t\c"
#    if [ `expr length $2` -lt 38 ]; then
#	echo "\t\c"
#    fi
#    $HTTEST -se $2 2> .${LOG}.log > .${LOG}.log
#    RC=$?
#    if [ $RC -ne 0 ]; then
#	echo "FAILED"
#	cat .${LOG}.log
#	echo ""
#	rm .${LOG}.log
##	tail -30 .${LOG}.log
##	echo "\nsee `pwd`/.${LOG}.log for more details"
#    else
#	END=`date '+%s'`
#	DIFF=`expr $END - $START`
#	echo "OK ($DIFF)"
#	rm .${LOG}.log
#    fi
else
    $HTTEST $@
    RC=$?
fi

if [ $RC -ne 0 ]; then
    sleep 3
fi

exit $RC
