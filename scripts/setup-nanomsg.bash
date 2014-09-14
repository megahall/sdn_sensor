#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f ${BASH_SOURCE[0]}))"
source "${script_directory}/../sdn_sensor_rc"

cd "${build_directory}/external/nanomsg"

# XXX: requires ~800MB of packages for asciidoc
# --enable-doc \

./configure \
--prefix=/usr/local \
--enable-debug \
--enable-nanocat \
--enable-symlinks \
--enable-shared \
--enable-static

make clean
make

sudo make install
sudo ldconfig
