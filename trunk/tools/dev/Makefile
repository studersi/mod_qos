top_srcdir   = ../../httpd
top_builddir = ../../httpd
srcdir       = ../../httpd/support
builddir     = ../../httpd/support
VPATH        = ../../httpd/support

PROGRAMS = regex
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


stack: stack.c
	cc -Wall -g -o $@ $<

clean:
	rm *.o stack regex
