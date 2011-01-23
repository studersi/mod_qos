#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Id: rweb2qos.sh,v 1.6 2011-01-22 09:39:38 pbuchbinder Exp $
#

declare -a A_NAME
declare -a A_PATTERN
declare -a A_NAME_SHAD
declare -a A_PATTERN_SHAD

IN=$1
ONCE=1

if [ -z "$IN" ]; then
  echo "Usage: `basename $0` <rule file>"
  exit 1
fi

printArray() {
  if [ $ONCE -eq 1 ]; then
    ONCE=0
    pattern=$1
    index=${#A_NAME[*]}
    i=0
    while [ $i -lt $index ]; do
      n=${A_NAME[$i]}
      p=${A_PATTERN[$i]}
      echo "# $i> $n $p"
      let i=$i+1
    done
  fi
}

copyShad() {
  index=${#A_NAME_SHAD[*]}
  i=0
  while [ $i -lt $index ]; do
    A_NAME[$i]=${A_NAME_SHAD[$i]}
    A_PATTERN[$i]=${A_PATTERN_SHAD[$i]}
    let i=$i+1
  done
}

insertArray() {
  n=$1
  p=$2
  inserted=0
  index=${#A_NAME[*]}
  i=0
  j=0
  while [ $i -lt $index ]; do
    n1=${A_NAME[$i]}
    p1=${A_PATTERN[$i]}
    if [ $inserted -eq 0 -a `expr length $n` -gt `expr length $n1` ]; then
      A_NAME_SHAD[$j]=$n
      A_PATTERN_SHAD[$j]=$p
      inserted=1
      let j=$j+1
    fi
    A_NAME_SHAD[$j]=$n1
    A_PATTERN_SHAD[$j]=$p1
    let i=$i+1
    let j=$j+1
  done
  if [ $inserted -eq 0 ]; then
    A_NAME_SHAD[$j]=$n
    A_PATTERN_SHAD[$j]=$p    
  fi
  copyShad
}

resolve() {
  pattern=$1
  index=${#A_NAME[*]}
  i=0
  while [ $i -lt $index ]; do
    n=${A_NAME[$i]}
    p=${A_PATTERN[$i]}
    esc=$(echo $p | sed -e 's/\\/\\\\/g' -e 's/\//\\\//g' -e 's/&/\\\&/g')
    pattern=`echo $pattern | sed -e "s/$n/$esc/g"`
    let i=$i+1
  done
  RESOLVED=$pattern
}

# main
MAX=`wc -l $IN | awk '{print $1}'`
count=0
while [ $count -lt $MAX ]; do
  let count=$count+1
  #echo "# line $count"
  line=`head -$count $IN | tail -1`
  name=`echo $line | awk '{print $1}'`
  if [ `echo $name | egrep -c "^#.*"` -gt 0 ]; then
    # suppress comments
    name=""
  fi
  if [ -n "$name" ]; then
    if [ $name = "GET" -o $name = "POST" ]; then
      # new rule:
      #printArray
      path=`echo $line | cut -d ' ' -f 2`
      query=""
      all_query=`echo $line | cut -d ' ' -f 3-`
      for E in `echo $all_query | tr "&" "\n"`; do
	if [ -n $E -a $E != "-" ]; then
	  resolve $E
	  if [ -z $query ]; then
	    query="($RESOLVED[&]?)"
	  else
	    query="$query|($RESOLVED[&]?)"
	  fi
	fi
      done
      if [ "$query" != "" ]; then
	query="\?($query)*"
      fi
      id=`printf "%.4d" $count`
      echo "QS_PermitUri +RW$id deny \"^$path$query\$\""
    else
      # new pattern:
      pattern=`echo $line | cut -d ' ' -f 2-`
      resolve $pattern
      #echo "# $index add pattern [$name] [$RESOLVED]"
      insertArray "$name" "$RESOLVED"
    fi
  fi
done
