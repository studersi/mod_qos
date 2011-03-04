#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.50])
AC_INIT(mod_qos, 9.0, pbuchbinder@users.sourceforge.net)
AC_CONFIG_SRCDIR([src/qscheck.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netdb.h stdlib.h string.h strings.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([ftruncate gethostbyname memset regcomp select socket strchr strerror strrchr strstr])

# START customize settings
AC_ARG_ENABLE([use-static], AS_HELP_STRING(--enable-use-static,Try to use archives instead of shared libraries))
AC_ARG_ENABLE([full-static], AS_HELP_STRING(--enable-full-static,Try to compile a statical linked executable))
AC_ARG_ENABLE([ssl], AS_HELP_STRING(--disable-ssl,Disable ssl support (not supported yet)))

AC_ARG_WITH(apr,AS_HELP_STRING(--with-apr=PATH,path to apr-1-config script),
	[if test ! -x $withval/apr-1-config; then AC_MSG_ERROR($withval/apr-1-config do not exist or is not executable); else APR_CONFIG="$withval/apr-1-config"; fi],
	[APR_CONFIG="apr-1-config"])
AC_ARG_WITH(apr-util,AS_HELP_STRING(--with-apr-util=PATH,path to apu-1-config script),
	[if test ! -x $withval/apu-1-config; then AC_MSG_ERROR($withval/apu-1-config do not exist or is not executable); else APU_CONFIG="$withval/apu-1-config"; fi],
	[APU_CONFIG="apu-1-config"])
AC_ARG_WITH(pcre,AS_HELP_STRING(--with-pcre=PATH,path to pcre-config script),
	[if test ! -x $withval/pcre-config; then AC_MSG_ERROR($withval/pcre-config do not exist or is not executable); else PCRE_CONFIG="$withval/pcre-config"; fi],
	[PCRE_CONFIG="pcre-config"])
AC_ARG_WITH(png,AS_HELP_STRING(--with-png=PATH,path to libpng-config script),
	[if test ! -x $withval/libpng-config; then AC_MSG_ERROR($withval/libpng-config do not exist or is not executable); else PNG_CONFIG="$withval/libpng-config"; fi],
	[PNG_CONFIG="libpng-config"])
AC_ARG_WITH(ssl,AS_HELP_STRING(--with-ssl=PATH,path to openssl source),
	[if test ! -d $withval; then AC_MSG_ERROR($withval is not a directory); else OPENSSL_LIB_PATH="-L${withval}"; OPENSSL_INCLUDES="-I${withval}/include"; fi],
	[OPENSSL_LIB_PATH=""; OPENSSL_INCLUDES=""])

APR_VERSION=`$APR_CONFIG --version`
if test ! "$?" = "0"; then
  echo "libapr is missing, use --with-apr=PATH"
  exit -1
fi
APU_VERSION=`$APU_CONFIG --version`
if test ! "$?" = "0"; then
  echo "libaprutil is missing, use --with-apr-util=PATH"
  exit -1
fi
PCRE_VERSION=`$PCRE_CONFIG --version`
if test ! "$?" = "0"; then
  echo "libpcre is missing, use --with-pcre=PATH to specify the location of your pcre library"
  exit -1
fi
PNG_VERSION=`$PNG_CONFIG --version`
if test ! "$?" = "0"; then
  echo "libpng is missing, use --with-png=PATH to specify the location of your png library"
  #exit -1
fi

# Store settings for includes, libs and flags
INCLUDES="`$APR_CONFIG --includes` `$APU_CONFIG --includes` $OPENSSL_INCLUDES"
CFLAGS="`$APR_CONFIG --cflags` `$PCRE_CONFIG --cflags` `$PNG_CONFIG --cflags` $CFLAGS $INCLUDES"
CPPFLAGS="`$APR_CONFIG --cppflags` $CPPFLAGS"
LIBS="$OPENSSL_LIB_PATH -lssl -lcrypto `$APR_CONFIG --link-ld`  `$APU_CONFIG --link-ld` `$APR_CONFIG --libs` `$APU_CONFIG --libs` `$PCRE_CONFIG --libs` `$PNG_CONFIG --libs` -lz"

# if link static
if test "$enable_full_static" = "yes"; then
  LDFLAGS="-all-static"
fi

# if link static
if test "$enable_use_static" = "yes"; then
  LDFLAGS="-static"
fi
# END	 customize settings

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
