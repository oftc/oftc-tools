#!/bin/sh
set -e
aclocal-1.9
automake-1.9 --add-missing
autoconf
./configure $@
