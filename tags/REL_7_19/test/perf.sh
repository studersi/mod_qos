#!/bin/sh

./sleep.sh
./htt.sh -s ./scripts/QS_Load_plain.htt
echo `date '+%S'`
./sleep.sh
./htt.sh -s ./scripts/QS_Load_plain.htt
echo `date '+%S'`

./sleep.sh
./htt.sh -s ./scripts/QS_Load_loc.htt
echo `date '+%S'`
./sleep.sh
./htt.sh -s ./scripts/QS_Load_loc.htt
echo `date '+%S'`
