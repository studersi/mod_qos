#!/bin/sh

RC=0
START=`date '+%s'`
if [ "$1" = "-s" -o "$1" = "-se" ]; then
    LOG=`basename $2`
    echo -e "run (`date '+%a %b %d %H:%M:%S %Y'`) $2\t\c"
    ./bin/httest1 $2 2>&1 > .${LOG}.log
    RC=$?
    if [ $RC -ne 0 ]; then
	echo "FAILED"
	tail -30 .${LOG}.log
    else
	END=`date '+%s'`
	DIFF=`expr $END - $START`
	echo "OK ($DIFF)"
	rm .${LOG}.log
    fi
else
    ./bin/httest1 $@
fi
exit $RC
