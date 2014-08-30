#!/bin/bash

set -e -x

if [[ $EUID -ne 0 ]]; then
    echo "$0 must be run as root"
    exit 1
fi

debug=0
setup=0

while getopts ":ds" optopt; do
    case "${optopt}" in
        d)
            debug=1
            ;;
        s)
            setup=1
            ;;
        *)
            echo "invalid command line options"
            exit 1
            ;;
    esac
done


script_directory="$(dirname $(readlink -f ${BASH_SOURCE[0]}))"
source "${script_directory}/../sdn_sensor_rc"
script_directory="$(dirname $(readlink -f ${BASH_SOURCE[0]}))"

export RTE_SDK="${HOME}/src/dpdk"
export RTE_TOOLS="${RTE_SDK}/tools"
export RTE_NIC_BIND="${RTE_TOOLS}/dpdk_nic_bind.py"

export PCI_ID_1="0000:01:00.0"
export PCI_ID_2="0000:01:00.1"

"${RTE_NIC_BIND}" --status | fgrep "${PCI_ID_1}"
"${RTE_NIC_BIND}" -b none          "${PCI_ID_1}"
"${RTE_NIC_BIND}" -b igb           "${PCI_ID_1}"
"${RTE_NIC_BIND}" --status | fgrep "${PCI_ID_1}"

"${RTE_NIC_BIND}" --status | fgrep "${PCI_ID_2}"
"${RTE_NIC_BIND}" -b none          "${PCI_ID_2}"
"${RTE_NIC_BIND}" -b igb_uio       "${PCI_ID_2}"
"${RTE_NIC_BIND}" --status | fgrep "${PCI_ID_2}"

modprobe igb || true
ip link set dev em1 up
ip addr add 192.168.2.6/24 dev em1 || true

if [[ $setup -gt 0 ]]; then
    echo "setup only, stopping"
    exit 0
fi

cd "${script_directory}/.."

if [[ $debug -gt 0 ]]; then
    gdb "${script_directory}/../src/sdn_sensor"
else
    "${script_directory}/../src/sdn_sensor"
fi
