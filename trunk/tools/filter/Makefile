top_srcdir   = /home/pbu/workspace/mod-qos/httpd
top_builddir = /home/pbu/workspace/mod-qos/httpd
srcdir       = /home/pbu/workspace/mod-qos/httpd/support
builddir     = /home/pbu/workspace/mod-qos/httpd/support
VPATH        = /home/pbu/workspace/mod-qos/httpd/support
DISTCLEAN_TARGETS = apxs apachectl dbmmanage log_server_status \
	logresolve.pl phf_abuse_log.cgi split-logfile envvars-std

CLEAN_TARGETS = suexec

PROGRAMS = qsfilter
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



