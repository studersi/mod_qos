top_srcdir   = ../../httpd
top_builddir = ../../httpd
srcdir       = ../../httpd/support
builddir     = ../../httpd/support
VPATH        = ../../httpd/support

PROGRAMS = regex b64 crs mem json wlsg
TARGETS  = $(PROGRAMS)

PROGRAM_LDADD        = $(UTIL_LDFLAGS) $(PROGRAM_DEPENDENCIES) $(EXTRA_LIBS) $(AP_LIBS)
PROGRAM_DEPENDENCIES = 

include $(top_builddir)/build/rules.mk

all: stack

regex_OBJECTS = regex.lo
regex_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
regex: $(regex_OBJECTS)
	$(LINK) $(regex_LTFLAGS) -static $(regex_OBJECTS) $(regex_LDADD)
	strip regex

b64_OBJECTS = b64.lo
b64_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
b64: $(b64_OBJECTS)
	$(LINK) $(b64_LTFLAGS) -static $(b64_OBJECTS) $(b64_LDADD)
	strip b64

crs_OBJECTS = crs.lo
crs_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
crs: $(crs_OBJECTS)
	$(LINK) $(crs_LTFLAGS) -static $(crs_OBJECTS) $(crs_LDADD)
	strip crs

mem_OBJECTS = mem.lo
mem_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
mem: $(mem_OBJECTS)
	$(LINK) $(mem_LTFLAGS) -static $(mem_OBJECTS) $(mem_LDADD)

json_OBJECTS = json.lo
json_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
json: $(json_OBJECTS)
	$(LINK) $(json_LTFLAGS) -static $(json_OBJECTS) $(json_LDADD)

wlsg_OBJECTS = wlsg.lo
wlsg_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
wlsg: $(wlsg_OBJECTS)
	$(LINK) $(wlsg_LTFLAGS) -static $(wlsg_OBJECTS) $(wlsg_LDADD)


stack: stack.c
	cc -Wall -O3 -o $@ $<

clean:
	rm *.o stack regex b64 crs mem json wlsg
