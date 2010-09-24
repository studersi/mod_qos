#!/bin/sh
cd `dirname $0` 

echo "/app/test" > access_log
echo "/other" >> access_log
echo "/m/this?name=val&more" >> access_log
echo "/app/mo^\"'re?name=value" >> access_log
echo "/app/this/cont?n=1&v=2" >> access_log
echo "/app/this/cont?v=1&n=2" >> access_log
echo "/app/this/cont" >> access_log
echo "/app/this/cont" >> access_log
echo "/app/this/cont?name%c4=value%c3" >> access_log
echo "/app/this/cont2?name%c4=value%c3" >> access_log
echo "/app/sp;v1.1%20?show_all" >> access_log
echo "/app/f/main.do?show=7834639&infoWord=Yes+Go&refN=98876&code=rk1lhTLn266YBx9\$\$" >> access_log
echo "/app/sp2�/mo.re�?name=+\$m?ore&n=b" >> access_log
echo "/app/test/__JDbhLdSs4dpOhE1LmbspyhEshuV.Ss__/b;XXX=Abc!-22!-33!44!55" >> access_log
echo "/app/test/__JDbhLdSs4qpOhE1LmbspOhELmbhuV.Ss__/b;XXX=Abc!-22!-33!44!55888888%C3" >> access_log
echo "/app/test/__JDbhLdSs4qpOhE1kajji78oJa8HLmbsp_-*other?name=value" >> access_log
echo "/app/test/sub?n=v#u?as" >> access_log
echo "//app/test/?n=http://a.b.c/i.t??" >> access_log
echo "/?n=n" >> access_log
echo "/app/test?l=x/\\\\\\\"oM=\\\"javascript:alert(true)\\\"\\\"" >> access_log
echo "/app/test?n&m=1" >> access_log
echo "/app/test?n=m&=" >> access_log
echo "/app/test?&n=m&=" >> access_log
echo "/app/test?n=&=" >> access_log
echo "/app/test?n=" >> access_log
echo "/app/test?=" >> access_log
echo "/app/ervlet?action=search&ret=http%3A%2F%2Fserver%2Fapp&name=value&&name=value" >> access_log
echo "/app/ervlet?other=search&ret=http%3A%2F%2Fserver%2Fapp&name=value&&name=value" >> access_log
echo "/app/k.x/umlhex\xc3\xbcurl%C3%BC/?Cmd=new" >> access_log
echo "/o-b/test.php?blah1=&blah2=" >> access_log

if [ -n "$1" ]; then
    ../../util/src/qsfilter2 -e -i access_log $@
    exit 0
fi

../../util/src/qsfilter2 -e -i access_log -m 2>&1 | grep -v "mod_qos version" > qm2.txt
DLINES=`diff qm2.txt.ref qm2.txt | wc -l`
if [ $DLINES -ne 4 ]; then
    echo "ERROR diff qm2.txt.ref qm2.txt"
    diff qm2.txt.ref qm2.txt
    exit 1
fi
../../util/src/qsfilter2 -e -i access_log 2>&1 | grep -v "mod_qos version" > q2.txt
DLINES=`diff q2.txt.ref q2.txt | wc -l`
if [ $DLINES -ne 4 ]; then
    echo "ERROR diff q2.txt.ref q2.txt"
    diff q2.txt.ref q2.txt
    exit 1
fi

rm access_log
