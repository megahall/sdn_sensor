#!/bin/bash

set -e -x

export CC=clang

# install the following additional packages:
# libunwind-setjmp0
# libunwind-setjmp0-dev
# libunwind7
# libunwind7-dev

autoconf

./configure \
--enable-autogen \
--prefix=/usr/local/jemalloc \
--with-jemalloc-prefix=je_ \
--enable-stats \
--enable-prof \
--enable-prof-libunwind \
--with-static-libunwind=/usr/lib/x86_64-linux-gnu/libunwind-x86_64.a \
--enable-fill \
--enable-valgrind \
--enable-dss \
--enable-xmalloc \
--disable-lazy-lock

#--with-private-namespace=je_ \

#make
#sudo make install
