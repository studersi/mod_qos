#!/bin/sh

cd `dirname $0`
set -e
set -u

T=10

dest=pbuchbinder,mod-qos@web.sourceforge.net:htdocs

echo "copy manpages"
scp ../*1.html ${dest}/
sleep $T
echo "copy images"
scp ../images/directive_seq.gif ${dest}/images/
scp ../images/directive_seq.gif ${dest}/images/mod_qos_seq.gif
scp ../images/directive_seq.gif ${dest}/mod_qos_seq.gif
scp ../images/download.jpg ${dest}/images/
sleep $T
#scp ../images/link.png ${dest}/images/
#scp ../images/ClientPrefer.png ${dest}/images/
#scp ../images/SrvMinDataRate.png ${dest}/images/
#scp ../images/LimitCount.png ${dest}/images/
#scp ../images/LimitCountExample.png ${dest}/images/
#scp ../images/ClosedLoop.png ${dest}/images/
#scp ../images/Serialization.png ${dest}/images/
#scp ../images/Events.png ${dest}/images/
#scp ../images/Rule.png ${dest}/images/
#scp ../images/qsloc.png ${dest}/images/
#scp ../images/qsloc1.png ${dest}/images/
#scp ../images/qsloc2.png ${dest}/images/
#scp ../images/qsloc3.png ${dest}/images/
#scp ../images/UserTracking.png ${dest}/images/
#scp ../images/QS_ClientEventBlockCount.png ${dest}/images/
#scp ../images/qslog_spreadsheet_example.png ${dest}/images/
#scp ../images/qslogFormat.png ${dest}/images/
scp ../images/*.png ${dest}/images/
scp ../images/mod_qos.gif ${dest}/images/
scp ../qsfilter2_process.gif ${dest}/
scp ../favicon.ico ${dest}/
sleep $T
echo "copy html files"
scp index.html ${dest}/
scp ../dos.html ${dest}/
scp ../glossary.html ${dest}/
scp ../MESSAGES.txt ${dest}/
scp ../LICENSE.txt ${dest}/
scp ../headerfilterrules.txt ${dest}/

echo "sample"
scp ../../test24/htdocs/errorpages/cookie-ir.shtml ${dest}/


