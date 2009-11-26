#!/bin/sh

RC=0
if [ "$1" = "-s" -o "$1" = "-se" ]; then
    echo -e "run $2\t\c"
    ./bin/httest1 $2 > .htt.log
    RC=$?
    if [ $RC -ne 0 ]; then
	echo "FAILED"
	tail -30 .htt.log
    else
	echo "OK"
	rm .htt.log
    fi
else
    ./bin/httest1 $@
fi
exit $RC
