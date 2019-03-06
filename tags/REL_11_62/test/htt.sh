#!/bin/sh

RC=0
if [ "$1" = "-s" -o "$1" = "-se" ]; then
    LOG=`basename $2`
    echo "run (`date '+%a %b %d %H:%M:%S %Y'`) $2\t\c"
    ./bin/httest $2 2>&1 > .${LOG}.log
    RC=$?
    if [ $RC -ne 0 ]; then
	echo "FAILED"
	tail -30 .${LOG}.log
    else
	echo "OK"
	rm .${LOG}.log
    fi
else
    ./bin/httest $@
fi
exit $RC
