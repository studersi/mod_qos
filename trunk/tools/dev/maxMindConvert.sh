#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# Converts GeoLite2 Country CSV files into the a format
# which can be loaded by mod_qos (similar to GeoLite Legacy).
#
# The GeoLite2-Country-CSV_<date>.zip archive usually contains
# the IP range/block defintion file "GeoLite2-Country-Blocks-IPv4.csv"
# as well as the ISO 3166 country code block mapping file
# "GeoLite2-Country-Locations-en.csv".
#
# The script uses the mod_qos binaries net2range and qsgeo.
#

block=GeoLite2-Country-Blocks-IPv4.csv
list=GeoLite2-Country-Locations-en.csv
net2range=./net2range
qsgeo=../../util/src/qsgeo

rm -f tmp.txt
for E in `grep -v geoname_id $list | awk -F',' '{print $1 "," $3 "," $5}'`; do
  blockid=`echo $E | awk -F',' '{print $1}'`
  country=`echo $E | awk -F',' '{print $3}'`
  if [ -z "$country" ]; then
      country=`echo $E | awk -F',' '{print $2}'`
  fi
  for net in `grep ",$blockid," $block | awk -F',' '{print $1}'`; do
      range=`${net2range} $net`
      netstart=`echo $range | awk -F',' '{print $3}'`
      netend=`echo $range | awk -F',' '{print $4}'`
      echo "$netstart,$netend,\"$country\"" >> tmp.txt
  done
done
cat tmp.txt | sort -n > tmp.sorted.txt
${qsgeo} -d tmp.sorted.txt -l

