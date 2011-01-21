#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Id: rweb2qos.sh,v 1.5 2011-01-21 22:59:32 pbuchbinder Exp $
#

declare -a A_NAME
declare -a A_PATTERN

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
      echo "$i> $n $p"
      let i=$i+1
    done
  fi
}

sortArray() {
  index=${#A_NAME[*]}
  i=0
  let index=$index-1
  while [ $i -lt $index ]; do
    let j=$i+1
    n1=${A_NAME[$i]}
    p1=${A_PATTERN[$i]}
    n2=${A_NAME[$j]}
    p2=${A_PATTERN[$j]}
    if [ `expr length $n1` -lt `expr length $n2` ]; then
      A_NAME[$i]=$n2
      A_NAME[$j]=$n1
      A_PATTERN[$i]=$p2
      A_PATTERN[$j]=$p1
      i=0
    fi
    let i=$i+1
  done
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
      #echo "$index add pattern [$name] [$RESOLVED]"
      # TODO: insert instead of sort
      A_NAME[$index]="$name"
      A_PATTERN[$index]="$RESOLVED"
      sortArray
    fi
  fi
done
