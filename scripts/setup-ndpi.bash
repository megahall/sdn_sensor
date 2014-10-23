#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"

cd "${build_directory}/external/ndpi"

autoreconf -ivf

./configure \
--prefix=/usr/local \
--enable-silent-rules \
--enable-shared \
--enable-static \
--with-pic

make
sudo make install

echo "ndpi built successfully"

exit 0
