#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${build_directory}"

sloccount --follow --personcost 130000 --addlang makefile external/dpdk-helpers scripts src analytics
