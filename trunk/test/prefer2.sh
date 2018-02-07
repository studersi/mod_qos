#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`
PFX=[`basename $0`]

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
sleep 1
# ----------------------------------------------------------------------------------
echo "$PFX dropping normal clients"
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- prefer2.sh" >>  logs/error_log
echo "SET maxclients=60" > scripts/maxclients
./run.sh -s scripts/QS_ClientPrefer20.htt 1>/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    echo "QS_ClientPrefer20.htt FAILED - 1"
    exit 1
fi
messages=`../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep -c "mod_qos(066)" | awk '{print $1}'`
type=`../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep "penalty=4 0x00" | grep -c "mod_qos(066)" | awk '{print $1}'`
echo "$PFX $messages connections blocked"
if [ $messages -eq 0 ]; then
    ../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep "mod_qos(066)"
    echo "$PFX failed: got NO mod_qos(066) errors ($messages)"
    exit 1
fi
if [ $type -ne $messages ]; then
    ../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep "mod_qos(066)"
    echo "PFX failed: wrong message type ($messages vs $type)"
    exit 1
fi

# ----------------------------------------------------------------------------------
echo "$PFX not reaching the limit for normal (no errors)"
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- prefer2.sh" >>  logs/error_log
echo "SET maxclients=58" > scripts/maxclients
./run.sh -s scripts/QS_ClientPrefer20.htt 1>/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    echo "QS_ClientPrefer20.htt FAILED - 2"
    exit 1
fi
messages=`../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep -c "mod_qos(066)"  | awk '{print $1}'`
echo "$PFX $messages connections blocked"
if [ $messages -ne 0 ]; then
    ../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep "mod_qos(066)"
    echo "$PFX failed: got mod_qos(066) errors ($messages)"
    exit 1
fi

# ----------------------------------------------------------------------------------
./ctl.sh restart -D max_clients -D cc > /dev/null
for E in `seq 100`; do
    ./run.sh -s scripts/QS_ClientPrefer20err.htt 2>/dev/null 1>/dev/null
done
sleep 12
echo "$PFX block clients which have violated QS_SrvMinDataRate rule"
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- prefer2.sh" >>  logs/error_log
echo "SET maxclients=58" > scripts/maxclients
./run.sh -s scripts/QS_ClientPrefer20.htt 1>/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    echo "QS_ClientPrefer20.htt FAILED - 3"
    exit 1
fi
messages=`../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep -c "mod_qos(066)"  | awk '{print $1}'`
echo "$PFX $messages connections blocked"
if [ $messages -eq 0 ]; then
    ../util/src/qstail -i logs/error_log -p "prefer2.sh" | grep "mod_qos(066)"
    echo "$PFX failed: got no mod_qos(066) errors ($messages)"
    exit 1
fi


echo "$PFX normal end"
exit 0

