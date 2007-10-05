#!/bin/sh

echo "/app/test" > access_log
echo "/other" >> access_log
echo "/m/this?name=val" >> access_log
echo "/app/mo^\"'re?name=value" >> access_log
echo "/app/this/cont" >> access_log
echo "/app/this/cont?name=value" >> access_log
echo "/app/sp;v1.1%20?show_all" >> access_log
echo "/app/f/main.do?show=7834639&infoWord=Yes+Go&refN=98876&code=rk1lhTLn266YBx9$$" >> access_log
echo "/app/sp2ä/mo.reö?name=+\$m?ore&n=b" >> access_log
echo "/app/test/__JDbhLdSs4dpOhE1LmbspyhEshuV.Ss__/b;XXX=Abc!-22!-33!44!55" >> access_log
echo "/app/test/__JDbhLdSs4qpOhE1LmbspOhELmbhuV.Ss__/b;XXX=Abc!-22!-33!44!55888888" >> access_log

./qsfilter2 -i access_log $@

rm access_log
