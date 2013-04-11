#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Id: qslog.sh,v 2.15 2013-04-11 18:31:14 pbuchbinder Exp $
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
        writeapacheD)
	  # %h %t %>s %b %D %{Event}e
	  echo "127.0.0.1 [24/Aug/2011:18:11:00 +0200] 200 1000 52637 A01,A02"
	  echo "127.0.0.1 [24/Aug/2011:18:11:30 +0200] 200 2000 152637 A01"
          echo "127.0.0.1 [24/Aug/2011:18:12:00 +0200] 200 1000 52637 A01,X02" 
	  echo "127.0.0.1 [24/Aug/2011:18:13:00 +0200] 200 1000 52637 -"
	  echo "127.0.0.1 [24/Aug/2011:18:14:00 +0200] 200 1000 52637 -"
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
 	echo "$PFX custom"
        (printf "2 4 6\n8 10 12\n"; ./sleep.sh 1>/dev/null; sleep 2) | ../util/src/qslog -f saA -o qs.log
	if [ `grep -c "s;10;a;7;A;9;" qs.log` -eq 0 ]; then
	  cat qs.log
	  echo "$PFX FAILED"
	  exit 1
	fi
	echo "$PFX OK"
	;;
	apache)
	# apache access log test using piped logging
	rm -f qs.log
	rm -f qs.log.detailed
	./sleep.sh
 	echo "$PFX apache"
	./qslog.sh test writeapache | ../util/src/qslog -f I....RSB.TkC -o qs.log -c qslog.conf
	if [ `grep -c 'r/s;3;req;236;b/s;590;esco;59;1xx;0;2xx;177;3xx;0;4xx;0;5xx;59;av;1;<1s;177;1s;0;2s;0;3s;0;4s;59;5s;0;>5s;0;ip;3;usr;0;qV;0;qS;0;qD;0;qK;0;qT;0;qL;0;qs;0;' qs.log` -ne 2 ]; then
	    cat qs.log
	    echo "$PFX FAILED"
	    exit 1
	fi
	if [ `grep -c '01;r/s;1;req;118;b/s;295;1xx;0;2xx;59;3xx;0;4xx;0;5xx;59;av;2;<1s;59;1s;0;2s;0;3s;0;4s;59;5s;0;>5s;0;qV;0;qS;0;qD;0;qK;0;qT;0;qL;0;qs;0;' qs.log.detailed` -ne 2 ]; then
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
	echo "$PFX OK"
	;;
        apacheD)
	# %D: The time taken to serve the request, in microseconds
	# E: comma separated list of event strings
	echo "$PFX D E"
	rm -f qs.log
	./qslog.sh test writeapacheD | ../util/src/qslog -f I..SBDE -o qs.log -p 2>/dev/null 1>/dev/null
	if [ `grep -c "b/s;16;" qs.log` -lt 1 ]; then
	  echo "$PFX failed, wrong bytes/sec"
	fi
	if [ `grep -c "b/s;50;" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong bytes/sec"
	fi
	if [ `grep -c "avms;52;av;0;" qs.log` -lt 1 ]; then
	  echo "$PFX failed, wrong average req time"
	fi
	if [ `grep -c "avms;102;av;0;" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong average req time"
	fi
	# first two req within first minute:
	if [ `grep -c "A01;2;A02;1" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong events"
	fi
	# second minute:
	if [ `grep -c "A01;1;A02;0;X02;1" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong events"
	fi
	# third minute
	if [ `grep -c "A01;0;A02;0;X02;0" qs.log` -ne 1 ]; then
	  echo "$PFX failed, wrong events"
	fi
	echo "$PFX OK"
	;;
	pc)
	echo "$PFX pc"
	./qslog.sh test writeapache 0 | ../util/src/qslog -f I....RSB.TkC -pc > pc
	if [ `grep -c "127.0.0.1;req;236;errors;0;1xx;0;2xx;236;3xx;0;4xx;0;5xx;0;av;0;<1s;236;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;" pc` -eq 0 ]; then
	    echo "$PFX FAILED (.1)"
	    exit 1
	fi
	if [ `grep -c "127.0.0.2;req;118;errors;0;1xx;0;2xx;118;3xx;0;4xx;0;5xx;0;av;0;<1s;118;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;" pc` -eq 0 ]; then
	    echo "$PFX FAILED (.2)"
	    exit 1
	fi
	if [ `grep -c "127.0.0.3;req;118;errors;118;1xx;0;2xx;0;3xx;0;4xx;0;5xx;118;av;4;<1s;0;1s;0;2s;0;3s;0;4s;118;5s;0;>5s;0;" pc` -eq 0 ]; then
	    echo "$PFX FAILED (.3)"
	    exit 1
	fi
	rm -f pc
	echo "$PFX OK"
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
	echo "$PFX log4j"
	# offline foreign log
	rm -f qs.log
	./qslog.sh test writelog4j | ../util/src/qslog -f ......IB.TS -o qs.log -p 2>/dev/null 1>/dev/null
	if [ `grep -c 'r/s;4;req;240;b/s;600;1xx;0;2xx;180;3xx;0;4xx;0;5xx;60;av;1;<1s;180;1s;0;2s;0;3s;0;4s;60;5s;0;>5s;0;ip;3;usr;0;qV;0;qS;0;qD;0;qK;0;qT;0;qL;0;qs;0;' qs.log` -ne 2 ]; then
	    echo "$PFX FAILED"
	    exit 1
	fi
	echo "$PFX OK"
	;;
	avms)
	echo "$PFX avms"
	# offline analysis measuring average req time in ms
	# verification: 
	#   cat qslog.data | awk '{print $(NF-8)}' |  awk '{total+=$NF/1000} END{print total/106}'
	rm -f qs.log
	cat qslog.data  | ../util/src/qslog -f I....RSB.D -p -o qs.log 2>/dev/null 1>/dev/null
	if [ `grep -c "r/s;1;req;106;b/s;10192;1xx;0;2xx;101;3xx;5;4xx;0;5xx;0;avms;2206;av;2;<1s;59;1s;0;2s;0;3s;16;4s;4;5s;21;>5s;6;ip;1;usr;0;" qs.log` -ne 1 ]; then
	  echo "$PFX FAILED"
	  exit 1
	fi
	echo "$PFX OK"
	;;
    esac
    ;;
    *)
      echo "Usage: `basename $0` run|count|test <mode>"
      exit 1
    ;;
esac

exit 0
