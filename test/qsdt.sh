#!/bin/sh

cd `dirname $0`
PFX=[`basename $0`]

echo "$PFX > process ../tools/dev/duration.log"
if [ `../util/src/qsdt  -i ' ([a-z0-9]+) [A-Z]+ ' -s 'Received Request' -e 'Received Response' ../tools/dev/duration.log | grep -c -e 138 -e 61238 -e 48311 -e 13989` -ne 4 ]; then
    echo "$PFX FAILED (1)"
    exit 1
fi

if [ `cat ../tools/dev/duration.log | ../util/src/qsdt  -i ' ([a-z0-9]+) [A-Z]+ ' -s 'Received Request' -e 'Received Response' | grep -c -e 138 -e 61238 -e 48311 -e 13989` -ne 4 ]; then
    echo "$PFX FAILED (2)"
    exit 1
fi

echo "$PFX < OK"
exit 0
