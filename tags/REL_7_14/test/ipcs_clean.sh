#!/bin/sh
#
# deletes shared memory segments and semaphore arrays
# which may left after unclean shutdown
#

PFX=[`basename $0`]
cd `dirname $0`

COMPS="apache.pid apache1.pid"
for E in $COMPS; do
    if [ -f logs/${E} ]; then
	ps -p `cat logs/${E}`
	if [ $? -ne 1 ] ;then
	    echo "$PFX: stop server pid=`cat logs/${E}` first"
	    exit 1
	fi
    fi
done

QS_UID=`id`
QS_UID_STR=`expr "$QS_UID" : 'uid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`

echo "$PFX: delete shared memory segments"
for E in `ipcs -m | grep $QS_UID_STR | awk '{print $2}'`; do
    ipcs -m | grep $QS_UID_STR | head -1
    ipcrm -m $E
done

echo "$PFX: delete semaphore arrays"
for E in `ipcs -s | grep $QS_UID_STR | awk '{print $2}'`; do
    ipcs -s | grep $QS_UID_STR | head -1
    ipcrm -s $E
done

exit 0
