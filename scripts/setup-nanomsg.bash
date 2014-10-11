#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f ${BASH_SOURCE[0]}))"
source "${script_directory}/../sdn_sensor_rc"

cd "${build_directory}/external/nanomsg"

if [[ ! -f configure ]]; then
    autoreconf -ifv
fi

./configure \
--prefix=/usr/local \
--enable-debug \
--enable-nanocat \
--enable-symlinks \
--enable-shared \
--enable-static

# XXX: requires ~800MB of packages for asciidoc
# --enable-doc \

make clean
make
sudo make install
sudo ldconfig
