#! /bin/bash -e

autoheader
aclocal
autoconf
autoreconf -fvi
automake --add-missing
./configure --prefix=/tmp/usr --enable-pgsql --enable-roaming --enable-debug
make

