#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f ${BASH_SOURCE[0]}))"

cd "${script_directory}"

thread_count=$(grep '^core id' /proc/cpuinfo | sort -u | wc -l)

export RTE_SDK="${script_directory}"
export RTE_TARGET="x86_64-native-linuxapp-clang"

export EXTRA_CFLAGS="-g -fPIC -msse4"

#make config T="${RTE_TARGET}"
cp config.txt build/.config

#make clean
make -j "${thread_count}"

cd "${script_directory}/examples"
make -j "${thread_count}"
