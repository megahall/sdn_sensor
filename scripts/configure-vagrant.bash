#!/bin/bash

set -e -x

if [[ $EUID -ne 0 ]]; then
    echo "$0 must be run as root"
    exit 1
fi

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"

export RTE_SDK="${build_directory}/external/dpdk"
export RTE_TOOLS="${RTE_SDK}/tools"
export RTE_NIC_BIND="${RTE_TOOLS}/dpdk_nic_bind.py"

export CORE_MASK=$("${script_directory}/find-dpdk-settings.pl" -c)
export PCI_ID=$("${script_directory}/find-dpdk-settings.pl" -p | awk '/^eth1 / { print $2; }')

echo "CORE_MASK ${CORE_MASK}"
echo "PCI_ID ${PCI_ID}"

conf_input="${script_directory}/../conf/sdn_sensor_vagrant.example"
conf_output="${script_directory}/../conf/sdn_sensor_vagrant.json"

if [[ ! -e $conf_output ]]; then
    cat "${conf_input}" | envsubst > "${conf_output}"
fi

depmod -a
modprobe uio
modprobe igb_uio

"${RTE_NIC_BIND}" --status | fgrep "${PCI_ID}"
"${RTE_NIC_BIND}" -b none          "${PCI_ID}"
"${RTE_NIC_BIND}" -b igb_uio       "${PCI_ID}"
"${RTE_NIC_BIND}" --status | fgrep "${PCI_ID}"

echo "dpdk vagrant configuration completed successfully"

exit 0
