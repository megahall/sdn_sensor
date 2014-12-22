#!/bin/bash

set -e -x

if [[ $EUID -ne 0 ]]; then
    echo "$0 must be run as root"
    exit 1
fi

debug=0

while getopts ":dv" optopt; do
    case "${optopt}" in
        d)
            debug=1
            ;;
        *)
            echo "invalid command line options"
            exit 1
            ;;
    esac
done

script_directory="$(dirname $(readlink -f ${BASH_SOURCE}))"
source "${script_directory}/../sdn_sensor_rc"

cd "${build_directory}"

export NN_PRINT_ERRORS=1
#export NN_PRINT_STATISTICS=1

command_line="${build_directory}/src/sdn_sensor -c ${build_directory}/conf/sdn_sensor_vagrant.json"

if [[ $debug -gt 0 ]]; then
    gdb --args ${command_line}
else
    ${command_line}
fi

exit $?
