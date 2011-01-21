#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Id: rweb2qos.sh,v 1.3 2011-01-21 21:58:23 pbuchbinder Exp $
#

declare -a A_NAME
declare -a A_PATTERN

IN=$1

if [ -z "$IN" ]; then
  echo "Usage: `basename $0` <rule file>"
  exit 1
fi

resolve() {
  # TODO: sort (longest match first)
  pattern=$1
  index=${#A_NAME[*]}
  i=0
  while [ $i -lt $index ]; do
    n=${A_NAME[$i]}
    p=${A_PATTERN[$i]}
    esc=$(echo $p | sed -e 's/\\/\\\\/g' -e 's/\//\\\//g' -e 's/&/\\\&/g')
    pattern=`echo $pattern | sed -e "s/$n/$esc/g"`
    i=`expr $i + 1`
  done
  RESOLVED=$pattern
}

# main
MAX=`wc -l $IN | awk '{print $1}'`
count=0
while [ $count -lt $MAX ]; do
  count=`expr $count + 1`
  line=`head -$count $IN | tail -1`
  name=`echo $line | awk '{print $1}'`
  if [ `echo $name | egrep -c "^#.*"` -gt 0 ]; then
    # suppress comments
    name=""
  fi
  if [ -n "$name" ]; then
    if [ $name = "GET" -o $name = "POST" ]; then
      # new rule:
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
      A_NAME[$index]="$name"
      A_PATTERN[$index]="$RESOLVED"
    fi
  fi
done
