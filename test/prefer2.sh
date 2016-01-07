#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`
PFX=[`basename $0`]

ERRORS=0

#
# MaxClients      64
# QS_ClientPrefer 80
#
# P	  T	  Max
# 2	> 2	> 62
# 4	> 4	> 60
# 6	> 6	> 58
# 8	> 9	> 55
# 10	> 11	> 53
# 12	> 13	> 51

./ctl.sh restart -D max_clients -D cc > /dev/null


echo "$PFX dropping normal clients"
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- prefer2.sh" >>  logs/error_log
echo "SET maxclients=61" > scripts/maxclients
./run.sh -s scripts/QS_ClientPrefer20.htt
ERRORS=`expr $ERRORS + $?`
messages=`../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep -c "mod_qos(066)" | awk '{print $1}'`
echo "$PFX $messages clients blocked"
if [ $messages -eq 0 ]; then
    ../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep "mod_qos(066)"
    echo "$PFX failed: got mod_qos(066) no errors ($messages)"
    exit 1
fi

echo "$PFX not reaching the limit for normal (no errors)"
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- prefer2.sh" >>  logs/error_log
echo "SET maxclients=58" > scripts/maxclients
./run.sh -s scripts/QS_ClientPrefer20.htt
ERRORS=`expr $ERRORS + $?`
messages=`../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep -c "mod_qos(066)"  | awk '{print $1}'`
echo "$PFX $messages clients blocked"
if [ $messages -ne 0 ]; then
    ../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep "mod_qos(066)"
    echo "$PFX failed: got mod_qos(066) errors ($messages)"
    exit 1
fi


exit $ERRORS

