#! /bin/bash -e

autoheader
aclocal
autoconf
autoreconf -fvi
automake --add-missing
./configure --prefix=/tmp/usr --enable-mysql --enable-roaming
make

