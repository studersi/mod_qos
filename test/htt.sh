#!/bin/sh

RC=0
if [ "$1" = "-s" -o "$1" = "-se" ]; then
    echo -e "run $2\t\c"
    ./bin/httest $2 > .htt.log
    RC=$?
    if [ $RC -ne 0 ]; then
	echo "FAILED"
	tail .htt.log
    else
	echo "OK"
	rm .htt.log
    fi
else
    ./bin/httest $@
fi
exit $RC
