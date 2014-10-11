#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"

# install the following additional packages:
# libunwind-setjmp0
# libunwind-setjmp0-dev
# libunwind7
# libunwind7-dev

cd "${build_directory}/external/jemalloc"

if [[ ! -f configure ]]; then
    autoconf
fi

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

make dist
make
sudo make install
