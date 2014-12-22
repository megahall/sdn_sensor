#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"

cd "${build_directory}/external/lmdb/libraries/liblmdb"

make clean
make
make test
sudo make install
