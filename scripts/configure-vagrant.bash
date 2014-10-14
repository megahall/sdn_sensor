#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"

export CORE_MASK=$("${script_directory}/find-dpdk-settings.pl" -c)
export PCI_ID=$("${script_directory}/find-dpdk-settings.pl" -v | awk '/^virtio1 / { print $2; }')

echo "CORE_MASK ${CORE_MASK}"
echo "PCI_ID ${PCI_ID}"

conf_input="${script_directory}/../conf/sdn_sensor_vagrant.example"
conf_output="${script_directory}/../conf/sdn_sensor_vagrant.json"

if [[ ! -e $conf_output ]]; then
    cat "${conf_input}" | envsubst > "${conf_output}"
fi

exit 0
