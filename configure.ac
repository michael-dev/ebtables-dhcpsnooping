#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.50])
AC_INIT([dhcpsnoopingd], [0.2], [michael-dev@fami-braun.de])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
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

#check if we want a debug build
AC_ARG_ENABLE(debug, [  --enable-debug          enable debug output], [
	if test "x$enableval" != "xno"; then
		AC_DEFINE([DEBUG], , [Enable debug output])
	fi
])

#check if version is given
AC_ARG_WITH(rev, [  --with-rev          enable rev output], [
	if test "x$withval" != "x"; then
		AC_DEFINE_UNQUOTED([REV],"$withval",[revision])
	fi
])

#check if we want roaming
AC_ARG_ENABLE(roaming, [  --enable-roaming          enable roaming support], [
	if test "x$enableval" != "xno"; then
		AC_DEFINE([__USE_ROAMING__], , [Enable roaming support])
	fi
])

AC_ARG_WITH([nflog-group],
     	  [AS_HELP_STRING([--with-nflog-group], [nflog group id, defaults to 1])],
	  AC_DEFINE_UNQUOTED([NFLOG_GROUP], $withval , [nflog group]),
	  AC_DEFINE([NFLOG_GROUP], 1 , [nflog group]))

#check if we want mysql
AC_ARG_ENABLE(mysql, [  --enable-mysql          enable MySQL support], [
	if test "x$enableval" != "xno"; then
		AC_DEFINE([__USE_MYSQL__], , [Enable mysql support])
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
        	  [MYSQL_LIBS='-L/usr/lib/mysql -lmysqlclient'])
	        AC_SUBST([MYSQL_LIBS])
	fi
])

#check if we want pgsql
AC_ARG_ENABLE(pgsql, [  --enable-pgsql          enable PostgreSQL support], [
	if test "x$enableval" != "xno"; then
		AC_DEFINE([__USE_PGSQL__], , [Enable pgsql support])

        	# Get PgSQL library and include locations

                PKG_CHECK_MODULES([PGSQL], [libpq])

	        AC_ARG_WITH([pgsql-include-path],
        	  [AS_HELP_STRING([--with-pgsql-include-path],
	            [location of the PgSQL headers, defaults to pkg_config])],
        	  [PGSQL_CFLAGS="-I$withval"],
	          [])
        	AC_SUBST([PGSQL_CFLAGS])
        
	        AC_ARG_WITH([pgsql-lib],
        	  [AS_HELP_STRING([--with-pgsql-lib], [PgSQL libraries])],
	          [PGSQL_LIBS="$withval"],
        	  [])

	        AC_ARG_WITH([pgsql-lib-path],
        	  [AS_HELP_STRING([--with-pgsql-lib-path], [location of the PgSQL libraries])],
	          [PGSQL_LIBS="-L$withval $PGSQL_LIBS"],
        	  [])
	        AC_SUBST([PGSQL_LIBS])
	fi
])

AC_ARG_ENABLE(vlan, [  --enable-vlan          enable vlan support], [
	if test "x$enableval" != "xno"; then
		AC_DEFINE([__USE_VLAN__], , [Enable vlan support])
	fi
])

# Checks for header files.
AC_HEADER_STDC

# libnet.h
AC_CHECK_HEADER([libnet.h],
                [AC_DEFINE([HAVE_LIBNET_H], [1], [Define to 1 if you have <libnet.h>.])],
                [AC_MSG_ERROR([missing 'libnet.h', please install libnet package])])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

