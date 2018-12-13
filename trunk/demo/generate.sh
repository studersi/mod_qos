#!/bin/sh

ROOT=`pwd`
TOP=`dirname $ROOT`
QS_UID=`id`
QS_UID_STR=`expr "$QS_UID" : 'uid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
QS_UID=`id`
QS_GID=`expr "$QS_UID" : '.*gid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
QS_UID=`id`
QS_UID=`expr "$QS_UID" : 'uid=\([0-9]*\)'`
QS_PORT_BASE=`expr ${QS_UID} - 1000`
QS_PORT_BASE=`expr $QS_PORT_BASE '*' 120`
QS_PORT_BASE=`expr $QS_PORT_BASE + 5000`
QS_PORT_BASE1=`expr $QS_PORT_BASE + 1`
QS_PORT_BASE2=`expr $QS_PORT_BASE + 2`
QS_PORT_BASE3=`expr $QS_PORT_BASE + 3`
QS_PORT_BASE5=`expr $QS_PORT_BASE + 5`
QS_PORT_BASE6=`expr $QS_PORT_BASE + 6`
QS_PORT_BASE8=`expr $QS_PORT_BASE + 8`
QS_PORT_BASE9=`expr $QS_PORT_BASE + 9`
QS_PORT_BASE10=`expr $QS_PORT_BASE + 10`

echo "SET QS_PORT_BASE=$QS_PORT_BASE"   >  scripts/ports
echo "SET QS_PORT_BASE1=$QS_PORT_BASE1" >> scripts/ports
echo "SET QS_PORT_BASE2=$QS_PORT_BASE2" >> scripts/ports
echo "SET QS_PORT_BASE3=$QS_PORT_BASE3" >> scripts/ports
echo "SET QS_PORT_BASE5=$QS_PORT_BASE5" >> scripts/ports
echo "SET QS_PORT_BASE6=$QS_PORT_BASE6" >> scripts/ports
echo "SET QS_PORT_BASE8=$QS_PORT_BASE8" >> scripts/ports
echo "SET QS_PORT_BASE9=$QS_PORT_BASE9" >> scripts/ports
echo "SET QS_PORT_BASE10=$QS_PORT_BASE10" >> scripts/ports
echo "SET QS_HOME=`pwd`" >> scripts/ports
echo "SET QS_HOME_ENC=`pwd | sed s:/:%2F:g`" >> scripts/ports

echo "QS_PORT_BASE=$QS_PORT_BASE"   >  ports
echo "export QS_PORT_BASE"          >> ports
echo "QS_PORT_BASE1=$QS_PORT_BASE1" >> ports
echo "export QS_PORT_BASE1"         >> ports
echo "QS_PORT_BASE2=$QS_PORT_BASE2" >> ports
echo "export QS_PORT_BASE1"         >> ports

CONFFILES="conf/httpd.conf conf/httpd2.conf conf/logstash.conf"
for E in $CONFFILES; do
    sed <$E.tmpl >$E \
	-e "s;##ROOT##;$ROOT;g" \
	-e "s;##TOP##;$TOP;g" \
	-e "s;##USR##;$QS_UID_STR;g" \
	-e "s;##QS_PORT_BASE##;$QS_PORT_BASE;g" \
	-e "s;##QS_PORT_BASE1##;$QS_PORT_BASE1;g" \
	-e "s;##QS_PORT_BASE2##;$QS_PORT_BASE2;g" \
	-e "s;##QS_PORT_BASE3##;$QS_PORT_BASE3;g" \
	-e "s;##QS_PORT_BASE5##;$QS_PORT_BASE5;g" \
	-e "s;##QS_PORT_BASE6##;$QS_PORT_BASE6;g" \
	-e "s;##QS_PORT_BASE8##;$QS_PORT_BASE8;g" \
	-e "s;##QS_PORT_BASE9##;$QS_PORT_BASE9;g" \
	-e "s;##QS_PORT_BASE10##;$QS_PORT_BASE10;g"
done

if [ ! -d logs ]; then
    mkdir logs
fi

mkdir -p ../test/htdocs/demo/doc/images
cp ../doc/*.html ../test/htdocs/demo/doc/
cp ../doc/*.gif ../test/htdocs/demo/doc/
cp ../doc/*.jpg ../test/htdocs/demo/doc/
cp ../doc/*.ico ../test/htdocs/demo/doc/
cp ../doc/images/*.gif ../test/htdocs/demo/doc/images/
cp ../doc/images/*.jpg ../test/htdocs/demo/doc/images/
cp ../doc/images/*.png ../test/htdocs/demo/doc/images/
cp ../doc/images/mod_qos.gif ../test/htdocs/demo/doc/mod_qos_s.gif
cp conf/httpd.conf ../test/htdocs/demo/doc/
