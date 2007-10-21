top_srcdir   = ../../httpd
top_builddir = ../../httpd
srcdir       = ../../httpd/support
builddir     = ../../httpd/support
VPATH        = ../../httpd/support

PROGRAMS = qsfilter qsfilter2
TARGETS  = $(PROGRAMS)

PROGRAM_LDADD        = $(UTIL_LDFLAGS) $(PROGRAM_DEPENDENCIES) $(EXTRA_LIBS) $(AP_LIBS)
PROGRAM_DEPENDENCIES = 

include $(top_builddir)/build/rules.mk

install:
	@test -d $(DESTDIR)$(bindir) || $(MKINSTALLDIRS) $(DESTDIR)$(bindir)
	@test -d $(DESTDIR)$(sbindir) || $(MKINSTALLDIRS) $(DESTDIR)$(sbindir)
	@test -d $(DESTDIR)$(libexecdir) || $(MKINSTALLDIRS) $(DESTDIR)$(libexecdir)
	@cp -p $(top_builddir)/server/httpd.exp $(DESTDIR)$(libexecdir)
	@for i in apxs apachectl dbmmanage; do \
	    if test -f "$(builddir)/$$i"; then \
	        cp -p $$i $(DESTDIR)$(sbindir); \
	        chmod 755 $(DESTDIR)$(sbindir)/$$i; \
	    fi ; \
	done
	@if test -f "$(builddir)/envvars-std"; then \
	    cp -p envvars-std $(DESTDIR)$(sbindir); \
	    if test ! -f $(DESTDIR)$(sbindir)/envvars; then \
	        cp -p envvars-std $(DESTDIR)$(sbindir)/envvars ; \
	    fi ; \
	fi


qsfilter_OBJECTS = qsfilter.lo
qsfilter_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qsfilter: $(qsfilter_OBJECTS)
	$(LINK) $(qsfilter_LTFLAGS) $(qsfilter_OBJECTS) $(qsfilter_LDADD)


qsfilter2_OBJECTS = qsfilter2.lo
qsfilter2_LDADD = $(PROGRAM_LDADD) $(SSL_LIBS)
qsfilter2: $(qsfilter2_OBJECTS)
	$(LINK) $(qsfilter2_LTFLAGS) -static $(qsfilter2_OBJECTS) $(qsfilter2_LDADD)
	strip qsfilter2

