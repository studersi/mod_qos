#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Id$
#
# used by qslog.htt

cd `dirname $0`
PFX=[`basename $0`]

case "$1" in
    count)
      LINES=`cat qs.log* | wc -l`
      FILES=`ls -1 qs.log* | wc -l`
      echo "$LINES $FILES"
    ;;
    run)
      ./run.sh scripts/_qslog.htt 2>&1 | ../util/src/qsrotate -o qs.log -s 5
    ;;
    test)
    # stand alone tests
    shift
    case "$1" in
        writeapacheci)
          for E in `seq 12`; do
	    min=`printf "%.2d" $E`
	    echo "127.0.0.${E} [24/Aug/2011:18:${min}:00 +0200] \"/a/\" GET 200 2000 152637 <NULL> text/html"
          done
        ;;
        writeapacheD)
	  # %h %t %>s %b %D %{Event}e
	  echo "127.0.0.1 [24/Aug/2011:18:11:00 +0200] \"/a/\" 200 1000 52637 A01,A02 text/html"
	  echo "127.0.0.2 [24/Aug/2011:18:11:30 +0200] \"/a/\" 200 2000 152637 A01, text/html"
          echo "127.0.0.1 [24/Aug/2011:18:12:00 +0200] \"/b/\" 200 1000 52637 A01,X02 text/html" 
	  echo "127.0.0.1 [24/Aug/2011:18:13:00 +0200] \"/a/\" 200 1000 52637 - image/jpg"
	  echo "127.0.0.1 [24/Aug/2011:18:14:00 +0200] \"/a/\" 200 1000 52637 - application/pdf"
	  ;;
	writeapache)
	# test data for the apache access log test
	# - 4 req/sec
	# - 600 bytes/sec
	# - time: 1 sec av
	#   - 180 < 1 sec
	#   - 60  = 4 sec
	# - 180 200er
	# - 60 500er
	# - 3 ip
	delay=${2-"1680"}
	for min in `seq 0 1`; do
	    for sec in `seq 0 58`; do
		printf "127.0.0.1 - - [24/Aug/2011:18:%.2d:%.2d +0200] \"GET /htt/index.txt HTTP/1.1\" 200 100 \"Mozilla\" '0' 0 \"/htt/index.html?name=\\u0053\"\n" $min $sec
		printf "127.0.0.1 - - [24/Aug/2011:18:%.2d:%.2d +0200] \"GET /a/index.txt HTTP/1.1\" 200 100 \"Mozilla\" '0' 1 \"/a/index.html\"\n" $min $sec
		printf "127.0.0.2 - - [24/Aug/2011:18:%.2d:%.2d +0200] \"GET /b/pages/index.txt HTTP/1.1\" 200 200 \"Mozilla\" '0' 2 \"/b/pages/index.html\"\n" $min $sec
		printf "127.0.0.3 -    - [24/Aug/2011:18:%.2d:%.2d +0200] \"GET /c/index.txt HTTP/1.1\" 500 200 \"Mozilla\" '4' 3 \"/c/index.html\"\n" $min $sec
		if [ $delay -gt 0 ]; then
		    ./bin/sleep 990
		fi
	    done
	    ./bin/sleep $delay
	done
	sleep 1
	;;
        custom)
	rm -f qs.log
 	echo "$PFX > custom saA"
        (printf "2 4 6\n8 10 12\n3 4,000 -\n"; ./sleep.sh 1>/dev/null; sleep 2) | ../util/src/qslog -f saA -o qs.log
	if [ `grep -c "s;13;a;6;A;9;" qs.log` -eq 0 ]; then
	  cat qs.log
	  echo "$PFX FAILED"
	  exit 1
	fi
	echo "$PFX < OK"
	rm -f qs.log
 	echo "$PFX > custom saAM"
        (printf "2 4 6 19\n8 10 12 34\n3 4,000 6 12\n"; ./sleep.sh 1>/dev/null; sleep 2) | ../util/src/qslog -f saAM -o qs.log
	if [ `grep -c "s;13;a;6;A;8;M;34;" qs.log` -eq 0 ]; then
	  cat qs.log
	  echo "$PFX FAILED"
	  exit 1
	fi
	echo "$PFX < OK"
	;;
	apache)
	# apache access log test using piped logging
	rm -f qs.log
	rm -f qs.log.detailed
	./sleep.sh
 	echo "$PFX > apache"
	./qslog.sh test writeapache | ../util/src/qslog -f I....RSB.TkC -o qs.log -c qslog.conf
	if [ `grep -c 'r/s;3;req;236;b/s;590;esco;59;1xx;0;2xx;177;3xx;0;4xx;0;5xx;59;av;1;<1s;177;1s;0;2s;0;3s;0;4s;59;5s;0;>5s;0;ip;3;usr;0;' qs.log` -ne 2 ]; then
	    cat qs.log
	    echo "$PFX FAILED"
	    exit 1
	fi
	if [ `grep -c '01;r/s;1;req;118;b/s;295;1xx;0;2xx;59;3xx;0;4xx;0;5xx;59;av;2;<1s;59;1s;0;2s;0;3s;0;4s;59;5s;0;>5s;0;' qs.log.detailed` -ne 2 ]; then
	    cat qs.log.detailed
	    echo "$PFX FAILED (rule 01)"
	    exit 1
	fi
	if [ `grep -c '02;r/s;0;req;0;' qs.log.detailed` -ne 2 ]; then
	    cat qs.log.detailed
	    echo "$PFX FAILED (rule 02)"
	    exit 1
	fi
	if [ `grep -c '03;r/s;0;req;59;b/s;196;1xx;0;2xx;59;' qs.log.detailed` -ne 2 ]; then
	    cat qs.log.detailed
	    echo "$PFX FAILED (rule 03)"
	    exit 1
	fi
	echo "$PFX < OK"
	;;
        apacheD)
	# %D: The time taken to serve the request, in microseconds
	# E: comma separated list of event strings
	echo "$PFX > D E"
	rm -f qs.log
	rm -f qs.log.detailed
	./qslog.sh test writeapacheD | ../util/src/qslog -f I..CSBDE -o qs.log -p -c qslog.conf 2>/dev/null 1>/dev/null
	if [ `grep -c "b/s;16;" qs.log` -lt 1 ]; then
	  echo "$PFX failed, wrong bytes/sec"
	  exit 1
	fi
	if [ `grep -c "b/s;50;" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong bytes/sec"
	  exit 1
	fi
	if [ `grep -c "avms;52;av;0;" qs.log` -lt 1 ]; then
	  echo "$PFX failed, wrong average req time"
	  exit 1
	fi
	if [ `grep -c "avms;102;av;0;" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong average req time"
	  exit 1
	fi
	# first two req within first minute:
	if [ `grep -c "A01;2;A02;1" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong events"
	  exit 1
	fi
	# first detailed: 2x A01, 1x A02 for application 01 (/a)
	if [ `grep -c "18:12:00;01;r/s;0;req;2;b/s;50;1xx;0;2xx;2;3xx;0;4xx;0;5xx;0;avms;102;av;0;0-49ms;0;50-99ms;1;100-499ms;1;500-999ms;0;<1s;2;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;A01;2;A02;1" qs.log.detailed` -ne 1 ]; then
	  echo "$PFX failed, wrong detailed"
	  exit 1
	fi
	# second minute:
	if [ `grep -c "A01;1;A02;0;X02;1" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong events"
	  exit 1
	fi
	# detailed: one request, 1x A01, 1x X02 att application 02 (/b)
	if [ `grep -c "24.08.2011 18:13:00;02;r/s;0;req;1;b/s;16;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;avms;52;av;0;0-49ms;0;50-99ms;1;100-499ms;0;500-999ms;0;<1s;1;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;A01;1;X02;1" qs.log.detailed` -ne 1 ]; then
	  echo "$PFX failed, wrong detailed 2"
	  exit 1
	fi
	# third minute
	if [ `grep -c "A01;0;A02;0;X02;0" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong events"
	  exit 1
	fi
	# init event table
	echo "A01,A02,A03,A04" > event.conf
	echo "B01,B02,B03,B04," >> event.conf
	echo "C01,C02,C03,C04" >> event.conf
	echo "D01,D02,D03,D04" >> event.conf
	echo "X01,X02,X03,X04" >> event.conf
	rm -f qs.log
	QSEVENTPATH=`pwd`/event.conf; export QSEVENTPATH
	./qslog.sh test writeapacheD | ../util/src/qslog -f I..RSBDE -o qs.log -p 2>/dev/null 1>/dev/null
	# first two req within first minute:
	if [ `grep -c "A01;2;A02;1;A03;0;A04;0;B01;0;B02;0;B03;0;B04;0;C01;0;C02;0;C03;0;C04;0;D01;0;D02;0;D03;0;D04;0;X01;0;X02;0;X03;0;X04;0" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong events in initialized event list"
	  exit 1
	fi
	unset QSEVENTPATH
	rm -f event.conf
	echo "$PFX < OK"
	;;
	pc)
	echo "$PFX > pc"
	./qslog.sh test writeapache 0 | ../util/src/qslog -f I....RSB.TkC -pc 2>/dev/null > pc
	if [ `grep -c "127.0.0.1;req;236;errors;0;duration;60;bytes;23600;1xx;0;2xx;236;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;0;<1s;236;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;" pc` -eq 0 ]; then
	    echo "$PFX FAILED (.1)"
	    exit 1
	fi
	if [ `grep -c "127.0.0.2;req;118;errors;0;duration;60;bytes;23600;1xx;0;2xx;118;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;0;<1s;118;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;" pc` -eq 0 ]; then
	    echo "$PFX FAILED (.2)"
	    exit 1
	fi
	if [ `grep -c "127.0.0.3;req;118;errors;118;duration;60;bytes;23600;1xx;0;2xx;0;3xx;0;4xx;0;5xx;118;304;0;av;4;avms;4000;<1s;0;1s;0;2s;0;3s;0;4s;118;5s;0;>5s;0;" pc` -eq 0 ]; then
	    echo "$PFX FAILED (.3)"
	    exit 1
	fi
	rm -f pc
	./qslog.sh test writeapacheD | ../util/src/qslog -f I..RSBDEc -pc 2>/dev/null > pc
	if [ `grep -c "127.0.0.1;req;4;errors;0;duration;180;bytes;4000;1xx;0;2xx;4;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;52;<1s;4;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;ci;0;html;2;css/js;0;img;1;other;1;A01;2;A02;1;X02;1;" pc` -ne 1 ]; then
	    echo "$PFX FAILED (.4)"
	    exit 1
	fi
	if [ `grep -c "127.0.0.2;req;1;errors;0;duration;1;bytes;2000;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;152;<1s;1;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;ci;40;html;1;css/js;0;img;0;other;0;A01;1;" pc` -ne 1 ]; then
	    echo "$PFX FAILED (.5)"
	    exit 1
	fi
	./qslog.sh test writeapacheci | ../util/src/qslog -f I..RmSBDE -pc 2>/dev/null > pc
	if [ `grep -c "127.0.0.6;req;1;errors;0;duration;1;bytes;2000;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;152;<1s;1;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;GET;1;POST;0;ci;50;" pc` -ne 1 ]; then
	    echo "$PFX FAILED (.6)"
	    exit 1
	fi
	if [ `grep -c "127.0.0.10;req;1;errors;0;duration;1;bytes;2000;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;152;<1s;1;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;GET;1;POST;0;ci;17;" pc` -ne 1 ]; then
	    echo "$PFX FAILED (.7)"
	    exit 1
	fi
	if [ `grep -c "127.0.0.3;req;1;errors;0;duration;1;bytes;2000;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;152;<1s;1;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;GET;1;POST;0;ci;25;" pc` -ne 1 ]; then
	    echo "$PFX FAILED (.8)"
	    exit 1
	fi
	echo "127.0.0.1 [24/Aug/2011:18:11:00 +0200] \"/a/\" POST 200 1000 52637 49 text/html\n127.0.0.1 [24/Aug/2011:18:12:00 +0200] \"/a/\" GET 200 2000 10000 8 text/css" | ../util/src/qslog -f I..RmSBD.c -pc 2>/dev/null > pc
	if [ `grep -c "127.0.0.1;req;2;errors;0;duration;60;bytes;3000;1xx;0;2xx;2;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;31;<1s;2;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;GET;1;POST;1;ci;0;html;1;css/js;1;img;0;other;0;" pc` -eq 0 ]; then
	    echo "$PFX FAILED (.9)"
	    exit 1
	fi
	echo "127.0.0.1 [24/Aug/2011:18:11:00 +0200] 1\n127.0.0.1 [24/Aug/2011:13:11:00 +0200] 3\n127.0.0.1 [24/Aug/2011:18:11:00 +0200] 2" | ../util/src/qslog -f I..M -pc 2>/dev/null > pc
	if [ `grep -c "127.0.0.1;req;3;errors;0;duration;0;bytes;0;1xx;0;2xx;0;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;0;<1s;3;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;ci;0;M;3;" pc` -eq 0 ]; then
	    echo "$PFX FAILED (.10)"
	    exit 1
	fi
        rm pc
	QSEVENTPATH=qslog_events
	export QSEVENTPATH
	QSCOUNTERPATH=`pwd`/qslog_rules.conf
	export QSCOUNTERPATH
	cat qslog_counter.log | ../util/src/qslog -f I..S..M.E -pc >pc
	if [ `egrep -c "^1;.*SC01Limit;2;SC01Limit2;1;STATUS;0;SC01;18;SC02;0;AU04;0;AU05;0;" pc` -ne 1 ]; then
	    echo "$PFX FAILED counter IP1"
	    exit 1
	fi
	if [ `egrep -c "^3;.*SC01Limit;0;SC01Limit2;0;STATUS;0;SC01;7;SC02;0;AU04;0;AU05;0;" pc` -ne 1 ]; then
	    echo "$PFX FAILED counter IP3"
	    exit 1
	fi
	if [ `egrep -c "^4;.*SC01Limit;0;SC01Limit2;0;STATUS;0;SC01;27;SC02;0;AU04;0;AU05;26;" pc` -ne 1 ]; then
	    echo "$PFX FAILED counter IP4"
	    exit 1
	fi
	if [ `egrep -c "^5;.*4xx;4;5xx;17;.*SC01Limit;0;SC01Limit2;0;STATUS;2;SC01;0;SC02;0;AU04;0;AU05;0;" pc` -ne 1 ]; then
	    echo "$PFX FAILED counter IP5"
	    exit 1
	fi
	unset QSCOUNTERPATH
	unset QSEVENTPATH
	rm pc
	echo "$PFX < OK"
	;;
	pu)
	echo "$PFX > pu"
	rm -rf pu.csv
	echo "127.0.0.1 - - [28/Nov/2013:08:09:51 +0100] \"GET /cgi100/sleep.cgi?s=6 HTTP/1.1\" 200 5 \"-\" 3 6 - 6 id=UpbsR38AAQEAAB-yBPUAAAAD - - - 0 - 2 a=2 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /cgi100/sleep.cgi?s=6 HTTP/1.1\" 200 5 \"-\" 6 6 - 6 id=UpbsR38AAQEAAB-yBPUAAAAD - - - 0 - 2 a=2 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"POST /view HTTP/1.1\" 200 5 \"-\" 6 5 - 5 id=UpbsR38AAQEAAB-yBPkAAAAG - - - 0 - 6 a=6 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /index.html HTTP/1.1\" 500 5 \"-\" 6 4 - 4 id=UpbsR38AAQEAAB-yBPgAAAAE - - - 0 - 5 a=5 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /sap(hasd)mode;jsessionid=111111?name=value HTTP/1.1\" 403 5 \"-\" 0 4 - 4 id=UpbsR38AAQEAAB-yBPgAAAAE - - - 0 - 5 a=5 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /images/1.jpg HTTP/1.1\" 200 5 \"-\" 0 4 - 4 id=UpbsR38AAQEAAB-yBPgAAAAE - - - 0 - 5 a=5 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /images/2.jpg HTTP/1.1\" 200 5 \"-\" 2 4 - 4 id=UpbsR38AAQEAAB-yBPgAAAAE - - - 0 - 5 a=5 #8178" | ../util/src/qslog -f I....RSB.T -pu -o pu.csv 2>/dev/null
	if [ `grep -c "req;2;1xx;0;2xx;2;3xx;0;4xx;0;5xx;0;avms;4500;GET;/cgi100/sleep.cgi" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (pu query)"
	    exit 1
	fi
	if [ `grep -c "req;1;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;avms;6000;POST;/view" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (pu POST)"
	    exit 1
	fi
	if [ `grep -c "req;1;1xx;0;2xx;0;3xx;0;4xx;0;5xx;1;avms;6000;GET;/index.html" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (pu 500)"
	    exit 1
	fi
	if [ `grep -c "req;1;1xx;0;2xx;0;3xx;0;4xx;1;5xx;0;avms;0;GET;/sap(hasd)mode;jsessionid=111111" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (pu 500)"
	    exit 1
	fi
	if [ `grep -c "req;1;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;avms;0;GET;/images/1.jpg" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (pu same path)"
	    exit 1
	fi
	if [ `grep -c "req;1;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;avms;2000;GET;/images/2.jpg" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (pu same path 2)"
	    exit 1
	fi
	rm -rf pu.csv
	echo "$PFX < OK"
	;;
	puc)
	echo "$PFX > puc"
	rm -rf pu.csv
	echo "127.0.0.1 - - [28/Nov/2013:08:09:51 +0100] \"GET /cgi100/sleep.cgi?s=6 HTTP/1.1\" 200 5 \"-\" 3 6 - 6 id=UpbsR38AAQEAAB-yBPUAAAAD - - - 0 - 2 a=2 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /cgi100/sleep.cgi?s=6 HTTP/1.1\" 200 5 \"-\" 6 6 - 6 id=UpbsR38AAQEAAB-yBPUAAAAD - - - 0 - 2 a=2 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"POST /view HTTP/1.1\" 200 5 \"-\" 6 5 - 5 id=UpbsR38AAQEAAB-yBPkAAAAG - - - 0 - 6 a=6 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /index.html HTTP/1.1\" 500 5 \"-\" 6 4 - 4 id=UpbsR38AAQEAAB-yBPgAAAAE - - - 0 - 5 a=5 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /images/1.jpg HTTP/1.1\" 200 5 \"-\" 0 4 - 4 id=UpbsR38AAQEAAB-yBPgAAAAE - - - 0 - 5 a=5 #8178\n127.0.0.1 - - [28/Nov/2013:08:09:59 +0100] \"GET /images/2.jpg HTTP/1.1\" 200 5 \"-\" 2 4 - 4 id=UpbsR38AAQEAAB-yBPgAAAAE - - - 0 - 5 a=5 #8178" | ../util/src/qslog -f I....RSB.T -puc -o pu.csv 2>/dev/null
	if [ `grep -c "req;2;1xx;0;2xx;2;3xx;0;4xx;0;5xx;0;avms;4500;GET;/cgi100" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (puc query)"
	    exit 1
	fi
	if [ `grep -c "req;1;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;avms;6000;POST;/view" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (puc POST)"
	    exit 1
	fi
	if [ `grep -c "req;1;1xx;0;2xx;0;3xx;0;4xx;0;5xx;1;avms;6000;GET;/index.html" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (puc 500)"
	    exit 1
	fi
	if [ `grep -c "req;2;1xx;0;2xx;2;3xx;0;4xx;0;5xx;0;avms;1000;GET;/images" pu.csv` -ne 1 ]; then
	    echo "$PFX FAILED (puc same path)"
	    exit 1
	fi
	rm -rf pu.csv
	echo "$PFX < OK"
	;;
	writelog4j)
	for min in `seq 0 1`; do
	    for sec in `seq 0 59`; do
		printf "2010-04-14 20:%.2d:%.2d,464 | INFO     | org.hibernate.cfg.Configuration rmip=\"127.0.0.1\" bs='100' event='other text' t='0' rc=200\n" $min $sec
		printf "2010-04-14 20:%.2d:%.2d,464 | INFO  | org.hibernate.cfg.Configuration rmip=\"127.0.0.1\" bs='100' event='other text' t='0' rc=200\n" $min $sec
		printf "2010-04-14 20:%.2d:%.2d,464 | INFO  | org.hibernate.cfg.Configuration rmip=\"127.0.0.2\" bs='200' event='other text' t='0'    rc=200\n" $min $sec
		printf "2010-04-14 20:%.2d:%.2d,464 | INFO  | org.hibernate.cfg.Configuration rmip=\"127.0.0.3\" bs='200' event='other text' t='4' rc=500 \n" $min $sec
	    done
	done
	;;
	log4j)
	echo "$PFX > log4j"
	# offline foreign log
	rm -f qs.log
	./qslog.sh test writelog4j | ../util/src/qslog -f ......IB.TS -o qs.log -p 2>/dev/null 1>/dev/null
	if [ `grep -c 'r/s;4;req;240;b/s;600;1xx;0;2xx;180;3xx;0;4xx;0;5xx;60;av;1;<1s;180;1s;0;2s;0;3s;0;4s;60;5s;0;>5s;0;ip;3;usr;0;' qs.log` -ne 2 ]; then
	    echo "$PFX writelog4j FAILED"
	    exit 1
	fi
	if [  `grep -c "14.04.2010 20" qs.log` -lt 2 ]; then
	    echo "$PFX writelog4j date detection FAILED"
	    exit 1
	fi
	echo "$PFX < OK"
	;;
	datedata)
	echo "$PFX > datedata"
	rm -f qs.log
	cat qslog.2.data  | ../util/src/qslog -f ......t -p -o qs.log 2>/dev/null 1>/dev/null
	if [ `grep -c "req;2;b/s;0;1xx;0;2xx;0;3xx;0;4xx;0;5xx;0;avms;20;" qs.log` -ne 2 ]; then
	  echo "$PFX 1 FAILED"
	  exit 1
	fi
	if [ `grep -c "17:35:00;r/s;0;req;6;b/s;0;1xx;0;2xx;0;3xx;0;4xx;0;5xx;0;avms;20" qs.log` -ne 1 ]; then
	  echo "$PFX 1 (time) FAILED"
	  exit 1
	fi
	rm -f qs.log
	cat qslog.3.data  | ../util/src/qslog -f ....t -p -o qs.log 2>/dev/null 1>/dev/null
	if [ `grep -c "19.02.2016 09:33:00;r/s;0;req;4;b/s;0;1xx;0;2xx;0;3xx;0;4xx;0;5xx;0;avms;20" qs.log` -ne 1 ]; then
	  echo "$PFX 2 (time) FAILED"
	  exit 1
	fi

	echo "$PFX < OK"
	;;
	avms)
	echo "$PFX > avms"
	# offline analysis measuring average req time in ms
	# verification: 
	#   cat qslog.data | awk '{print $(NF-8)}' |  awk '{total+=$NF/1000} END{print total/106}'
	rm -f qs.log
	cat qslog.data  | ../util/src/qslog -f I....RSB.D -p -o qs.log 2>/dev/null 1>/dev/null
	if [ `grep -c "r/s;1;req;106;b/s;1019[12];1xx;0;2xx;101;3xx;5;4xx;0;5xx;0;avms;2206;av;2;0-49ms;6;50-99ms;12;100-499ms;41;500-999ms;0;<1s;59;1s;0;2s;0;3s;16;4s;4;5s;21;>5s;6;ip;1;usr;0;" qs.log` -ne 1 ]; then
	  echo "$PFX FAILED"
	  exit 1
	fi
	if [ `grep -c "05.04.2012 17" qs.log` -lt 1 ]; then
	  echo "$PFX date detection FAILED"
	  exit 1
	fi
	echo "$PFX < OK"
	;;
	gc)
	echo "$PFX > gc"
	rm -f gc.csv
	echo "[28/Jun/2014:09:17:35 +0200] 200 5\n[28/Jun/2014:09:17:35 +0200] 200 3\n[28/Jun/2014:09:17:35 +0200] 200 0\n[28/Jun/2014:09:17:35 +0200] 200 7\n[28/Jun/2014:09:17:35 +0200] 200 5\n[28/Jun/2014:09:17:35 +0200] 200 20\n[28/Jun/2014:09:17:35 +0200] 200 30\n[28/Jun/2014:09:17:35 +0200] 200 40\n[28/Jun/2014:09:17:35 +0200] 200 30\n[28/Jun/2014:09:17:35 +0200] 200 30\n[28/Jun/2014:09:17:35 +0200] 200 31\n[28/Jun/2014:09:17:35 +0200] 200 32\n[28/Jun/2014:09:17:35 +0200] 200 33\n[28/Jun/2014:09:17:35 +0200] 200 34\n[28/Jun/2014:09:17:35 +0200] 200 35\n[28/Jun/2014:09:17:35 +0200] 200 36\n[28/Jun/2014:09:17:35 +0200] 200 37\n[28/Jun/2014:09:17:35 +0200] 200 38\n[28/Jun/2014:09:17:35 +0200] 200 39\n[28/Jun/2014:09:18:35 +0200] 200 35\n[28/Jun/2014:09:19:35 +0200] 200 35\n[28/Jun/2014:09:20:12 +0200] 200 35\n[28/Jun/2014:09:20:35 +0200] 200 28\n[28/Jun/2014:09:21:35 +0200] 200 19\n[28/Jun/2014:09:22:35 +0200] 200 32\n[28/Jun/2014:09:23:35 +0200] 200 35\n[28/Jun/2014:09:24:35 +0200] 200 32\n[28/Jun/2014:09:25:35 +0200] 200 35\n[28/Jun/2014:09:26:35 +0200] 200 32\n[28/Jun/2014:09:27:35 +0200] 200 32\n[28/Jun/2014:09:28:35 +0200] 200 32\n[28/Jun/2014:09:29:35 +0200] 200 32\n[28/Jun/2014:09:30:35 +0200] 200 32\n[28/Jun/2014:09:31:35 +0200] 200 32\n[28/Jun/2014:09:32:35 +0200] 200 32\n[28/Jun/2014:09:33:35 +0200] 200 32\n[28/Jun/2014:09:34:35 +0200] 200 32\n[28/Jun/2014:09:35:35 +0200] 200 32\n[28/Jun/2014:09:36:35 +0200] 200 32\n[28/Jun/2014:09:37:35 +0200] 200 32" | ../util/src/qslog -f ..SU -p 2>/dev/null > gc.csv
	if [ `grep "2014 09:18" gc.csv | grep -c "req;19;"` -ne 1 ]; then
	  echo "$PFX FAILED: 17 - gc number of requests"
	  exit 1
	fi
	if [ `grep "2014 09:18" gc.csv | grep -c "usr;16;"` -ne 1 ]; then
	  echo "$PFX FAILED: 17 - gc number of users"
	  exit 1
	fi
	if [ `grep "2014 09:19" gc.csv | grep -c "req;1;"` -ne 1 ]; then
	  echo "$PFX FAILED: 18 - gc number of requests"
	  exit 1
	fi
	if [ `grep "2014 09:19" gc.csv | grep -c "usr;16;"` -ne 1 ]; then
	  echo "$PFX FAILED: 18 - gc number of users"
	  exit 1
	fi
	if [ `grep "2014 09:21" gc.csv | grep -c "usr;17;"` -ne 1 ]; then
	  echo "$PFX FAILED: 20 - gc number of users"
	  exit 1
	fi
	if [ `grep "2014 09:22" gc.csv | grep -c "usr;18;"` -ne 1 ]; then
	  echo "$PFX FAILED: 21 - gc number of users"
	  exit 1
	fi
	if [ `grep "2014 09:28" gc.csv | grep -c "usr;18;"` -ne 1 ]; then
	  echo "$PFX FAILED: 27 - gc number of users"
	  exit 1
	fi
	if [ `grep "2014 09:29" gc.csv | grep -c "usr;4;"` -ne 1 ]; then
	  echo "$PFX FAILED: 28 - gc number of users"
	  exit 1
	fi
	if [ `grep "2014 09:35" gc.csv | grep -c "usr;2;"` -ne 1 ]; then
	  echo "$PFX FAILED: 34 - gc number of users"
	  exit 1
	fi
	if [ `grep "2014 09:37" gc.csv | grep -c "usr;1;"` -ne 1 ]; then
	  echo "$PFX FAILED: 36 - gc number of users"
	  exit 1
	fi
	rm -f gc.csv
	echo "$PFX < OK"
	;;
        all)
	     ERRORS=0
	     ./run.sh -s ./scripts/qslog.htt
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.htt"
	     fi
	     ./qslog.sh test datedata
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test datedata"
	     fi
	     ./qslog.sh test log4j
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test log4j"
	     fi
	     ./qslog.sh test apache
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test apache"
	     fi
	     ./qslog.sh test apacheD
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test apacheD"
	     fi
	     ./qslog.sh test custom
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test custom"
	     fi
	     ./qslog.sh test pc
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test pc"
	     fi
	     ./qslog.sh test pu
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test pu"
	     fi
	     ./qslog.sh test puc
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test puc"
	     fi
	     ./qslog.sh test avms
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test avms"
	     fi
	     ./qslog.sh test gc
	     if [ $? -ne 0 ]; then
	       ERRORS=`expr $ERRORS + 1`
	       echo "FAILED qslog.sh test gc"
	     fi
	     if [ $ERRORS -eq 0 ]; then
	       echo "normal end"
	     else
	       echo "FAILED: $ERRORS erros"
	     fi
	     exit $ERRORS
	;;
    esac
    ;;
    *)
      echo "Usage: `basename $0` run|count|test <mode>"
      exit 1
    ;;
esac

exit 0
