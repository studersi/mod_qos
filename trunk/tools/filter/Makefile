top_srcdir   = ../../httpd
top_builddir = ../../httpd
srcdir       = ../../httpd/support
builddir     = ../../httpd/support
VPATH        = ../../httpd/support

#PROGRAMS = qsfilter qsfilter2
PROGRAMS = qsfilter2
TARGETS  = $(PROGRAMS)

PROGRAM_LDADD        = $(UTIL_LDFLAGS) $(PROGRAM_DEPENDENCIES) $(EXTRA_LIBS) $(AP_LIBS)
PROGRAM_DEPENDENCIES = 

include $(top_builddir)/build/rules.mk

#qsfilter_OBJECTS = qsfilter.lo
#qsfilter_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
#qsfilter: $(qsfilter_OBJECTS)
#	$(LINK) $(qsfilter_LTFLAGS) $(qsfilter_OBJECTS) $(qsfilter_LDADD)


qsfilter2_OBJECTS = qsfilter2.lo
qsfilter2_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qsfilter2: $(qsfilter2_OBJECTS)
	$(LINK) $(qsfilter2_LTFLAGS) -static $(qsfilter2_OBJECTS) $(qsfilter2_LDADD)
	strip qsfilter2

