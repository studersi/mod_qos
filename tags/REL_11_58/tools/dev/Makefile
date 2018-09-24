top_srcdir   = ../../httpd
top_builddir = ../../httpd
srcdir       = ../../httpd/support
builddir     = ../../httpd/support
VPATH        = ../../httpd/support

PROGRAMS = qsgrep qslog qsdt regex regexspeed b64 qnc crs mem json pws qssearch vszl stack2 rand qssyslog net2range VMB
TARGETS  = $(PROGRAMS)

PROGRAM_LDADD        = $(UTIL_LDFLAGS) $(PROGRAM_DEPENDENCIES) $(EXTRA_LIBS) $(AP_LIBS)
PROGRAM_DEPENDENCIES = 

include $(top_builddir)/build/rules.mk

regex_OBJECTS = regex.lo
regex_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
regex: $(regex_OBJECTS)
	$(LINK) $(regex_LTFLAGS) -static qs_util.o $(regex_OBJECTS) $(regex_LDADD)

qslog.c: qs_util.h qs_util.o
	if [ ! -r qslog.c ]; then ln -s ../../util/src/qslog.c .; fi

qsdt.c: qs_util.h qs_util.o
	if [ ! -r qsdt.c ]; then ln -s ../../util/src/qsdt.c .; fi

qsgrep.c: qs_util.h qs_util.o
	if [ ! -r qsgrep.c ]; then ln -s ../../util/src/qsgrep.c .; fi

regexspeed.c: qs_util.h qs_util.o
	if [ ! -r regexspeed.c ]; then ln -s ../../util/src/qsrespeed.c regexspeed.c; fi

regex.c: qs_util.h qs_util.o
	if [ ! -r regex.c ]; then ln -s ../../util/src/qsre.c regex.c; fi

qs_util.h:
	if [ ! -r qs_util.h ]; then ln -s ../../util/src/qs_util.h .; fi

qs_util.o:
	if [ ! -r qs_util.o ]; then ln -s ../../util/src/qs_util.o .; fi

qsgrep_OBJECTS = qsgrep.lo
qsgrep_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qsgrep: $(qsgrep_OBJECTS)
	$(LINK) $(qsgrep_LTFLAGS) -static qs_util.o $(qsgrep_OBJECTS) $(qsgrep_LDADD)

qslog_OBJECTS = qslog.lo
qslog_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qslog: $(qslog_OBJECTS)
	$(LINK) $(qslog_LTFLAGS) -static qs_util.o $(qslog_OBJECTS) $(qslog_LDADD)

qsdt_OBJECTS = qsdt.lo
qsdt_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qsdt: $(qsdt_OBJECTS)
	$(LINK) $(qsdt_LTFLAGS) -static qs_util.o $(qsdt_OBJECTS) $(qsdt_LDADD)

rand_OBJECTS = rand.lo
rand_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
rand: $(rand_OBJECTS)
	$(LINK) $(rand_LTFLAGS) -static $(rand_OBJECTS) $(rand_LDADD)

qssyslog_OBJECTS = qssyslog.lo
qssyslog_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qssyslog: $(qssyslog_OBJECTS)
	$(LINK) $(qssyslog_LTFLAGS) -static $(qssyslog_OBJECTS) $(qssyslog_LDADD)

net2range_OBJECTS = net2range.lo
net2range_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
net2range: $(net2range_OBJECTS)
	$(LINK) $(net2range_LTFLAGS) -static $(net2range_OBJECTS) $(net2range_LDADD)

stack2_OBJECTS = stack2.lo
stack2_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
stack2: $(stack2_OBJECTS)
	$(LINK) $(stack2_LTFLAGS) -static $(stack2_OBJECTS) $(stack2_LDADD)

regexspeed_OBJECTS = regexspeed.lo
regexspeed_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
regexspeed: $(regexspeed_OBJECTS) regexspeed.c
	$(LINK) $(regexspeed_LTFLAGS) -static qs_util.o $(regexspeed_OBJECTS) $(regexspeed_LDADD)
	strip regexspeed

b64_OBJECTS = b64.lo
b64_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
b64: $(b64_OBJECTS)
	$(LINK) $(b64_LTFLAGS) -static $(b64_OBJECTS) $(b64_LDADD)
	strip b64

qnc_OBJECTS = qnc.lo
qnc_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qnc: $(qnc_OBJECTS)
	$(LINK) $(qnc_LTFLAGS) -static $(qnc_OBJECTS) $(qnc_LDADD)
	strip qnc

crs_OBJECTS = crs.lo
crs_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
crs: $(crs_OBJECTS)
	$(LINK) $(crs_LTFLAGS) -static $(crs_OBJECTS) $(crs_LDADD)
	strip crs

mem_OBJECTS = mem.lo
mem_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
mem: $(mem_OBJECTS)
	$(LINK) $(mem_LTFLAGS) -static $(mem_OBJECTS) $(mem_LDADD)

vszl_OBJECTS = vszl.lo
vszl_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
vszl: $(vszl_OBJECTS)
	$(LINK) $(vszl_LTFLAGS) -static $(vszl_OBJECTS) $(vszl_LDADD)

json_OBJECTS = json.lo
json_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
json: $(json_OBJECTS)
	$(LINK) $(json_LTFLAGS) -static $(json_OBJECTS) $(json_LDADD)

qssearch_OBJECTS = qssearch.lo
qssearch_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qssearch: $(qssearch_OBJECTS)
	$(LINK) $(qssearch_LTFLAGS) -static $(qssearch_OBJECTS) $(qssearch_LDADD)

pws_OBJECTS = pws.lo
pws_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
pws: $(pws_OBJECTS)
	$(LINK) $(pws_LTFLAGS) -static $(pws_OBJECTS) $(pws_LDADD)

wlsg_OBJECTS = wlsg.lo
wlsg_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
wlsg: $(wlsg_OBJECTS)
	$(LINK) $(wlsg_LTFLAGS) -static $(wlsg_OBJECTS) $(wlsg_LDADD)

stack: stack.c
	cc -Wall -O3 -o $@ $<

VMB: VMB.c
	cc -O3 -pthread -o $@ $<

clean:
	rm -f *.o stack stack2 regex regexspeed b64 qnc crs mem vszl json pws qssearch rand qssyslog net2range VMB qsgrep qsgrep.c qslog qslog.c qsdt qstd.c

