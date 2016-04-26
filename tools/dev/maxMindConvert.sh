#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

block=GeoLite2-Country-Blocks-IPv4.csv
list=GeoLite2-Country-Locations-en.csv
rm -f tmp.txt
for E in `grep -v geoname_id $list | awk -F',' '{print $1 "," $3 "," $5}'`; do
  blockid=`echo $E | awk -F',' '{print $1}'`
  country=`echo $E | awk -F',' '{print $3}'`
  if [ -z "$country" ]; then
      country=`echo $E | awk -F',' '{print $2}'`
  fi
  for net in `grep ",$blockid," $block | awk -F',' '{print $1}'`; do
      range=`./net2range $net`
      netstart=`echo $range | awk -F',' '{print $3}'`
      netend=`echo $range | awk -F',' '{print $4}'`
      echo "$netstart,$netend,\"$country\"" >> tmp.txt
  done
done
cat tmp.txt | sort -n > tmp.sorted.txt
../../util/src/qsgeo -d tmp.sorted.txt -l

