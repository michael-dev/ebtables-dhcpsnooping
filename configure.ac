#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.50])
AC_INIT([dhcpsnoopingd], [0.2])
AC_CONFIG_SRCDIR([dhcpsnoopingd.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_LANG(C)
GCC_STACK_PROTECTOR

PKG_CHECK_MODULES(LIBNL, libnl-3.0)
AC_SUBST(LIBNL_CFLAGS)
AC_SUBST(LIBNL_LIBS)

PKG_CHECK_MODULES(LIBNLGENL, libnl-genl-3.0)
AC_SUBST(LIBNLGENL_CFLAGS)
AC_SUBST(LIBNLGENL_LIBS)

PKG_CHECK_MODULES(LIBNLNF, libnl-nf-3.0)
AC_SUBST(LIBNLNF_CFLAGS)
AC_SUBST(LIBNLNF_LIBS)

PKG_CHECK_MODULES(LIBNLROUTE, libnl-route-3.0)
AC_SUBST(LIBNLROUTE_CFLAGS)
AC_SUBST(LIBNLROUTE_LIBS)

#check if we want roaming
AC_ARG_ENABLE(roaming, [  --enable-roaming          enable roaming support], [
	ROAMING_FLAGS=-D__USE_ROAMING__
	AC_SUBST(ROAMING_FLAGS)
])

#check if we want mysql
AC_ARG_ENABLE(mysql, [  --enable-mysql          enable MySQL support], [
	MYSQL_FLAGS=-D__USE_MYSQL__
	AC_SUBST(MYSQL_FLAGS)
])

# Checks for header files.
AC_HEADER_STDC

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP

# check for mysql if it is enabled
if test -n "$MYSQL_FLAGS"; then
        # Get MySQL library and include locations
        AC_ARG_WITH([mysql-include-path],
          [AS_HELP_STRING([--with-mysql-include-path],
            [location of the MySQL headers, defaults to /usr/include/mysql])],
          [MYSQL_CFLAGS="-I$withval"],
          [MYSQL_CFLAGS='-I/usr/include/mysql'])
        AC_SUBST([MYSQL_CFLAGS])
        
        AC_ARG_WITH([mysql-lib-path],
          [AS_HELP_STRING([--with-mysql-lib-path], [location of the MySQL libraries])],
          [MYSQL_LIBS="-L$withval -lmysqlclient"],
          [MYSQL_LIBS='-lmysqlclient'])
        AC_SUBST([MYSQL_LIBS])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

