#!/bin/sh

cd `dirname $0`
set -e
set -u

dest=pbuchbinder,mod-qos@web.sourceforge.net:htdocs

echo "copy manpages"
scp ../*1.html ${dest}/
echo "copy images"
scp ../images/mod_qos_seq.gif ${dest}/images/
scp ../images/download.jpg ${dest}/images/
scp ../images/link.png ${dest}/images/
scp ../images/SrvMinDataRate.png ${dest}/images/
scp ../images/mod_qos_s.gif ${dest}/images/
scp ../qsfilter2_process.gif ${dest}/
scp ../favicon.ico ${dest}/
echo "copy html files"
scp index.html ${dest}/
scp ../dos.html ${dest}/
scp ../MESSAGES.txt ${dest}/
scp ../LICENSE.txt ${dest}/

