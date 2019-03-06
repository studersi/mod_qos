#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# Script to merge the output of several qslog 
# output files of different Apache Web servers
# into a single file.
#

# directory to search
directory=./tmp

# file to search
filter='*stat*log'

# parameters to collect
params='req;
b/s;
avms;
a;'

# -----------------
first=`find $directory -name "${filter}" | sort | tail -1`
others=`find $directory -name "${filter}" | sort | grep -v first`
all=`find $directory -name "${filter}" | sort`

# requires gnu awk
GAWK=awk

IFS='
'

# print file names (<dir>/<dir>/<file>)
printf ";"
for F in $all; do
  #filename=`basename $F`
  filename=`echo $F | awk -F'/' '{print $(NF-2) "/" $(NF-1) "/" $(NF) }'`
  printf "$filename"
  for N in $params; do
    printf ";;"
  done
done
echo ""

for E in `cat $first`; do
  time=`echo $E | ${GAWK} -F';' '{print $1}'`
  # determine if all files contains an entry of that time
  haveall=1
  for F in $others; do
    if [ `grep -c $time $F` -eq 0 ]; then
      haveall=0
    fi
  done
  if [ $haveall -eq 1 ]; then
    # prints all file entries on a single line
    printf "$time;"
    for F in $all; do
      line=`grep $time $F`
      for N in $params; do
	printf "$N"
	echo $line | \
	 ${GAWK} -F"$N" '{print $2}' | \
	 ${GAWK} -F';' '{printf $1 ";"}'
      done
    done
    echo ""
  fi
done
