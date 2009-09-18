top_srcdir   = ../../httpd
top_builddir = ../../httpd
srcdir       = ../../httpd/support
builddir     = ../../httpd/support
VPATH        = ../../httpd/support

PROGRAMS = regex b64
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
	##	strip b64


stack: stack.c
	cc -Wall -O3 -o $@ $<

clean:
	rm *.o stack regex b64
