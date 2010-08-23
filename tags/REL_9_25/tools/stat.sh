#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`
ELEMENTS="r/s req b/s av <1s 1s 2s 3s 4s 5s >5s ip usr qv qs qd qk qt ql sl m"
CSV=qslog.csv
if [ ! -d tmp ]; then
  mkdir tmp
fi

DA=`head -1 $CSV | awk '{print $1}'`
echo "<html><head><title>$DA</title></head><body>" > index.html
for E in $ELEMENTS; do
  FILE=`echo $E | sed -e "s:>:gt:g" -e "s:/:_:g"`
  ../util/src/qspng -i $CSV -o tmp/${FILE}.png -p "$E"
  echo "<img src=\"tmp/${FILE}.png\" /><br>" >> index.html
done

echo "</body></html>" >> index.html
