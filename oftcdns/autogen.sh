#!/bin/sh
set -e
set -x
aclocal-1.9
automake-1.9 --add-missing --foreign --copy
autoconf
./configure $@
