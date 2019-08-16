#! /bin/sh

set -e

autoheader
aclocal
autoconf
autoreconf -fvi
automake --add-missing
./configure --prefix=/tmp/usr --enable-pgsql --enable-roaming --enable-debug --enable-vlan --enable-ebtables --enable-nftables
make -j2

