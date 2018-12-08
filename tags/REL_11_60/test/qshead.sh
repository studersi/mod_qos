#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`
PFX=[`basename $0`]

echo "$PFX start"

lines=`printf "123\n456\n789\n" | ../util/src/qshead -p 456 | wc -l`
if [ $lines -ne 2 ]; then
  echo "$PFX FAILED $lines"
  exit 1
fi

echo "$PFX OK"
exit 0
