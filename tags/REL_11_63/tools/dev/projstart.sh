#!/bin/sh
cd `dirname $0`
cd ../..

lines=0
words=0
chars=0
for E in `find . -name Entries`; do
    dir=`dirname $E`
    dir=`dirname $dir`
    files=`cat $E | awk -F '/' '{print $2}'`
    for file in $files; do
	if [ -f $dir/$file -a `file $dir/$file | grep -c text` -gt 0 ]; then
	    echo "$dir/$file"
	    l=`wc -l $dir/$file | awk '{print $1}'`
	    w=`wc -w $dir/$file | awk '{print $1}'`
	    m=`wc -m $dir/$file | awk '{print $1}'`
	    lines=`expr $lines + $l`
	    words=`expr $lines + $w`
	    chars=`expr $lines + $m`
	fi
    done
done

echo " lines=$lines words=$words characters=$chars"
