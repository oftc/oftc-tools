#!/bin/sh
set -e
set -x
aclocal-1.10
automake-1.10 --add-missing --foreign --copy
autoconf
./configure $@
