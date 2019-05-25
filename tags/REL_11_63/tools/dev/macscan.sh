#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

NET=192.168.1

PATH=/usr/sbin:${PATH}
export PATH
if [ -f ./oui.txt ]; then
  macpfxfile="./oui.txt"
else 
  macpfxfile=`locate nmap-mac-prefixes | tail -1`
  if [ -z "$macpfxfile" ]; then
    macpfxfile=`locate oui.txt | tail -1`
  fi
  if [ -z "$macpfxfile" ]; then
    echo "you could download the MAC address block list from http://standards.ieee.org/regauth/oui/oui.txt"
  fi
fi
echo "$macpfxfile"

for E in `seq 255`; do
  ping -c 1 -W 1 ${NET}.${E} 2>/dev/null 1>/dev/null
  arpentry=`arp | grep -v incomplete | egrep "^${NET}.${E} "`
  if [ -n "$arpentry" ]; then
    echo "$arpentry" | awk '{printf $1 " \t" $3 " " $5}'
    macpfx=`echo $arpentry | awk '{print $3}' | sed -e "s;:;;g" | awk '{print substr($0,0,6)}'`
    if [ -n "$macpfxfile" ]; then
      pfx=`grep -i "$macpfx"  $macpfxfile`
      if [ -n "$pfx" ]; then
	echo " $pfx"
      else
	echo " -"
      fi
    else
      echo " ."
    fi
  fi
done

