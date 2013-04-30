#! /bin/bash -e

autoheader
aclocal
autoconf
automake --add-missing
./configure --prefix=/tmp/usr --enable-mysql --enable-roaming
make

