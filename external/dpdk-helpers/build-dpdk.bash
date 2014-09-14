#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f ${BASH_SOURCE[0]}))"

cd "${script_directory}"

thread_count=$(grep '^core id' /proc/cpuinfo | sort -u | wc -l)
thread_count=1

export RTE_SDK="${script_directory}"
export RTE_SDK_BIN="${script_directory}/build"
#export RTE_OUTPUT="${script_directory}/build"
export RTE_TARGET="x86_64-native-linuxapp-clang"
export RTE_ARCH="x86_64"

export EXTRA_CFLAGS="-g -O0 -fPIC -msse4"

#make config T="${RTE_TARGET}"
if [[ ! -f "build/.config" ]]; then
    cp config.txt build/.config
fi

make clean
make -j "${thread_count}"
make -j "${thread_count}" -C examples RTE_SDK=$(pwd) RTE_TARGET=build RTE_SDK_BIN=$(pwd)/build

sudo cp build/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.ko /lib/modules/$(uname -r)/kernel/drivers/uio/igb_uio.ko
sudo depmod -a
