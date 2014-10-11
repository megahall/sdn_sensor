#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"

cd "${build_directory}/external/spcdns"

# XXX switch to master version and find out how to build misc lib
make lib so

exit 0
