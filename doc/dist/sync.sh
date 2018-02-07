#!/bin/sh

cd `dirname $0`
set -e
set -u

dest=pbuchbinder,mod-qos@web.sourceforge.net:htdocs

echo "copy manpages"
scp ../*1.html ${dest}/
echo "copy images"
scp ../images/directive_seq.gif ${dest}/images/
scp ../images/directive_seq.gif ${dest}/images/mod_qos_seq.gif
scp ../images/download.jpg ${dest}/images/
scp ../images/link.png ${dest}/images/
scp ../images/ClientPrefer.png ${dest}/images/
scp ../images/SrvMinDataRate.png ${dest}/images/
scp ../images/LimitCount.png ${dest}/images/
scp ../images/LimitCountExample.png ${dest}/images/
scp ../images/ClosedLoop.png ${dest}/images/
scp ../images/Serialization.png ${dest}/images/
scp ../images/mod_qos.gif ${dest}/images/
scp ../qsfilter2_process.gif ${dest}/
scp ../favicon.ico ${dest}/
echo "copy html files"
scp index.html ${dest}/
scp ../dos.html ${dest}/
scp ../glossary.html ${dest}/
scp ../MESSAGES.txt ${dest}/
scp ../LICENSE.txt ${dest}/

