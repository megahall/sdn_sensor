#!/bin/bash

set -e -x

export CC="llvm-gcc"
export CXX="llvm-g++"
export CFLAGS="-std=gnu11"
export CXXFLAGS="-std=gnu++11"

export SDN_SENSOR_BASE=${SDN_SENSOR_BASE:-~/src/sdn_sensor}

echo "SDN_SENSOR_BASE set to ${SDN_SENSOR_BASE}"

# RE2

cd "${SDN_SENSOR_BASE}/external/re2"

make clean
make
make test
sudo make install
sudo ldconfig
make testinstall

# CRE2

cd "${SDN_SENSOR_BASE}/external/cre2"

sh autogen.sh
./configure \
--prefix=/usr/local \
--enable-maintainer-mode
make
sudo make install
