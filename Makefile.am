
sbin_PROGRAMS = dhcpsnoopingd


AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4
AM_CFLAGS = $(ROAMING_FLAGS) $(MYSQL_FLAGS) $(MYSQL_CFLAGS) $(LIBNL_CFLAGS) $(LIBNLGENL_CFLAGS) $(LIBNLNF_CFLAGS) $(LIBNLROUTE_CFLAGS) -Wall -D _FORTIFY_SOURCE=2 -O2 -g -fPIE -std=gnu99 -Wall -Werror
LIBS = $(MYSQL_LIBS) $(LIBNL_LIBS) $(LIBNLGENL_LIBS) $(LIBNLNF_LIBS) $(LIBNLROUTE_LIBS)
dhcpsnoopingd_SOURCES = src/debug.c src/cmdline.c src/dhcp-ack.c src/dhcp-req.c src/dhcpv4.c src/event.c src/main.c src/receive-bridge.c src/timer.c src/dhcp.c src/ebtables.c src/fdb.c src/mysql.c src/receive-nflog.c src/udp.c
