#!/bin/sh

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
echo "/app/f/main.do?show=7834639&infoWord=Yes+Go&refN=98876&code=rk1lhTLn266YBx9$$" >> access_log
echo "/app/sp2ä/mo.reö?name=+\$m?ore&n=b" >> access_log
echo "/app/test/__JDbhLdSs4dpOhE1LmbspyhEshuV.Ss__/b;XXX=Abc!-22!-33!44!55" >> access_log
echo "/app/test/__JDbhLdSs4qpOhE1LmbspOhELmbhuV.Ss__/b;XXX=Abc!-22!-33!44!55888888%C3" >> access_log
echo "/app/test/__JDbhLdSs4qpOhE1kajji78oJa8HLmbsp_-*other?name=value" >> access_log
echo "/app/test/sub?n=v#u?as" >> access_log
echo "//app/test/?n=http://a.b.c/i.t??" >> access_log
echo "/?n=n" >> access_log
echo "/app/test?l=x/\\\\\\\"oM=\\\"javascript:alert(true)\\\"\\\"" >> access_log

./qsfilter2 -e -i access_log $@

rm access_log
