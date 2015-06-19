#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f ${BASH_SOURCE}))"
source "${script_directory}/../sdn_sensor_rc"
cd "${script_directory}"

thread_count=$(grep '^core id' /proc/cpuinfo | sort -u | wc -l)
thread_count=1

export RTE_SDK="${build_directory}/external/dpdk"
export RTE_SDK_BIN="${RTE_SDK}/build"
#export RTE_OUTPUT="${RTE_SDK}/build"
export RTE_TARGET="x86_64-native-linuxapp-clang"
export RTE_ARCH="x86_64"
export RTE_INCLUDE="${RTE_SDK_BIN}/include"

export EXTRA_CFLAGS="-g -O2 -fPIC -msse4"

cd "${RTE_SDK}"

#make clean || true

if [[ ! -f ${RTE_SDK_BIN}/.config ]]; then
    mkdir -p "${RTE_SDK_BIN}"
    #make config T="${RTE_TARGET}"
    cp "${script_directory}/dpdk-config.txt" "${RTE_SDK_BIN}/.config"
fi

make -j "${thread_count}"
make -j "${thread_count}" -C examples "RTE_SDK=${RTE_SDK}" "RTE_TARGET=build" "RTE_SDK_BIN=${RTE_SDK}/build"
make -j "${thread_count}" -C app/test "RTE_SDK=${RTE_SDK}" "RTE_TARGET=build" "RTE_SDK_BIN=${RTE_SDK}/build"

sudo mkdir -p /lib/modules/$(uname -r)/kernel/drivers/uio
sudo cp build/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.ko /lib/modules/$(uname -r)/kernel/drivers/uio/igb_uio.ko
sudo depmod -a

echo "dpdk setup completed successfully"

exit 0
