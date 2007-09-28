#!/bin/sh


echo -e "/app/test\n/other\n/m/this?name=val\n/app/mo^\"'re?name=value\n/app/sp;v1.1%20?show_all\n/app/f/main.do?show=7834639&infoWord=Yes+Go&refN=98876&code=rk1lhTLn266YBx9$$\n/app/sp2/mo.re?name=+\$m?ore&n=b\n/app/test/__JDbhLdSs4qpOhE1LmbspOhELmbhuV.Ss__/b;XXX=Abc!-22!-33!44!55" | ./qsfilter $@

