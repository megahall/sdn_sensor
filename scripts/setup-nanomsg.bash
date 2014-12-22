#!/bin/bash

set -e -x

# start with g* for OS X
# then switch to without for Linux if needed
os=$(uname -s)
if [[ $os == "Darwin" ]]; then
    readlink_path=$(which greadlink)
    mktemp_path=$(which gmktemp)
    gsed_path=$(which gsed)
    is_linux=0
else
    readlink_path=$(which readlink)
    mktemp_path=$(which mktemp)
    gsed_path=$(which sed)
    is_linux=1
fi

echo $BASH_SOURCE
script_directory=$(dirname $(${readlink_path} -f $BASH_SOURCE))
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
if [[ $is_linux -gt 0 ]]; then
    sudo ldconfig
fi
