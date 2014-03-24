#!/bin/sh

cd `dirname $0`
. ./ports
wget -O - http://127.0.0.1:$QS_PORT_BASE6/console?action=limit\&address=$2\&event=$1 >/dev/null

