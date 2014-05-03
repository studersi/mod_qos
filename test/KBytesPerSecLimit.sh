#!/bin/sh
#
# export UC=uc1l2; ./KBytesPerSecLimit.sh ; sleep 600; export UC=uc1l3; ./KBytesPerSecLimit.sh
#

UC=${UC-uc1l2}
./ctl.sh stop
../httpd/httpd -d `pwd` -f conf/uc1.conf -D $UC
./sleep.sh
echo "$UC" >> logs/qs_log_v0
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch3.htt &
sleep 10
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch3.htt &
sleep 90
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch3.htt &
sleep 120
./run.sh -s scripts/UC1_QS_LocKBytesPerSecLimitMatch3.htt &

# V10.30
# -------------------
# uc1l2
# b/s;1676701;
# b/s;3112831;
# b/s;58453;
# b/s;4023081;
# b/s;72207;
# b/s;374134;
#     1552901 52%
#
# 02.05.2014 13:30:00
# -------------------
# uc1l2
# b/s;2976924;
# b/s;2961476;
# b/s;2980049;
# b/s;2976142;
# b/s;2976533;
# b/s;2603310;
#     2912406 97%
# 
# uc1l3
# b/s;2605553;
# b/s;2606859;
# b/s;2794323;
# b/s;2790405;
# b/s;2790797;
# b/s;2046036;
#     2605662 86%
#
# 03.05.2014 13:05:00
# -------------------
# uc1l2
# b/s;2960044;
# b/s;2978356;
# b/s;2811294;
# b/s;2790378;
# b/s;2959523;
# b/s;2434425;
#     2822337 94%
