#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"

# Note: RE2 uses some constructs which are forever incompatible with clang,
# because clang refuses to add support for them.

export CC="llvm-gcc"
export CXX="llvm-g++"
export CFLAGS="${CFLAGS} -std=gnu11"
export CXXFLAGS="${CXXFLAGS} -std=gnu++11"

# RE2

cd "${build_directory}/external/re2"

make clean
make
#make test
sudo make install
sudo ldconfig
make testinstall

# CRE2

cd "${build_directory}/external/cre2"

if [[ ! -f configure ]]; then
    sh autogen.sh
fi
./configure \
--prefix=/usr/local \
--enable-maintainer-mode
make
sudo make install
sudo ldconfig
