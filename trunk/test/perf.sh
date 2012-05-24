#!/bin/sh

# execute script against application server (no mod_qos)
./sleep.sh
./run.sh -s ./scripts/QS_Load_plain.htt
echo `date '+%S'`
./sleep.sh
./run.sh -s ./scripts/QS_Load_plain.htt
echo `date '+%S'`

# and now via proxy server haning mod_qos installed
./sleep.sh
./run.sh -s ./scripts/QS_Load_loc.htt
echo `date '+%S'`
./sleep.sh
./run.sh -s ./scripts/QS_Load_loc.htt
echo `date '+%S'`
