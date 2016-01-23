#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f ${BASH_SOURCE}))"
source "${script_directory}/../sdn_sensor_rc"
cd "${script_directory}"

thread_count=$(grep '^core id' /proc/cpuinfo | sort -u | wc -l)
#thread_count=1

export RTE_SDK="${build_directory}/external/dpdk"
export RTE_OUTPUT="${RTE_SDK}/build"
export RTE_TARGET="x86_64-native-linuxapp-gcc"
export RTE_ARCH="x86_64"
export RTE_INCLUDE="${RTE_OUTPUT}/include"

export EXTRA_CFLAGS="${CFLAGS}"

cd "${RTE_SDK}"

if [[ ! -f ${RTE_OUTPUT}/.config ]]; then
    mkdir -p "${RTE_OUTPUT}"
    make config T="${RTE_TARGET}"
    #cp "${script_directory}/dpdk-config.txt" "${RTE_OUTPUT}/.config"
fi

make clean || true

export MAKEFLAGS="-j${thread_count}"
make "RTE_OUTPUT=${RTE_OUTPUT}"
make install "T=${RTE_TARGET}" "O=build" "DESTDIR=build"
make -C app/test "T=${RTE_TARGET}" "RTE_SDK=${RTE_SDK}" "RTE_TARGET=build"
make -C examples "T=${RTE_TARGET}" "RTE_SDK=${RTE_SDK}" "RTE_TARGET=build"

sudo mkdir -p /lib/modules/$(uname -r)/kernel/drivers/uio
sudo cp build/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.ko /lib/modules/$(uname -r)/kernel/drivers/uio/igb_uio.ko
sudo depmod -a

echo "dpdk setup completed successfully"

exit 0
