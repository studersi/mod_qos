#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# Implements status change
#
# Parameters:
# $1  command to perform, either "init", "start", or "stop"
# $2  interface name, e.g eth0 or eth1
# $3  netmask used for this interface
# $4  broadcast address used for this interface
# $5  default gateway
# $6+ ip address to set (one or multiple)
#

cd `dirname $0`
PFX="[`basename $0`]:"
PATH=$PATH
export PATH

echo "`date` $@" >> ha.log

if [ -z "$6" ]; then
  echo "$PFX ERROR, to few arguments"
  exit 1
fi

CMD=$1
shift
INT=$1
shift
MASK=$1
shift
BCAST=$1
shift
GW=$1
shift

# clear/re-initialize the interface (plumb)
do_init() {
  if [ `uname -s` = "SunOS" ]; then
    ifconfig $INT plumb
  fi
  id=0
  ADDR=$1
  while [ -n "$ADDR" ]; do
    echo "$PFX init $INT:$id $ADDR"
    if [ `uname -s` = "SunOS" ]; then
      ifconfig $INT:$id plumb
    fi
    ifconfig $INT:$id $ADDR netmask $MASK broadcast $BCAST down
    id=`expr $id + 1`
    shift
    ADDR=$1
  done
}

# instance becomes active:
# - start the interfaces (UP)
# - gratuitous arp
# - add default route
# - restart services
do_start() {
  id=0
  ADDR=$1
  while [ -n "$ADDR" ]; do
    echo "$PFX start $INT:$id $ADDR"
    ifconfig $INT:$id $ADDR netmask $MASK broadcast $BCAST up
    #garp $$$
    id=`expr $id + 1`
    shift
    ADDR=$1
  done
  route add default gw $GW $INT
}

# instance becomes standby:
# - stop the interfaces (DOWN)
do_stop() {
  id=0
  ADDR=$1
  while [ -n "$ADDR" ]; do
    echo "$PFX stop $INT:$id $ADDR"
    ifconfig $INT:$id $ADDR netmask $MASK broadcast $BCAST down
    id=`expr $id + 1`
    shift
    ADDR=$1
  done
}

case $CMD in
  init)
    do_init $@
    ;;
  start)
    do_start $@
    ;;
  stop)
    do_stop $@
    ;;
  *)
    echo "$PFX ERROR, invalid command"
    exit 1
esac

echo "$PFX normal end"
exit 0
