#!/bin/bash

script_directory="$(dirname $(readlink -f ${BASH_SOURCE}))"

set -e -x

cd "${script_directory}/../src"

if [[ -d cov-int ]]; then
    rm -rf cov-int
fi

make clean

# XXX: Get Coverity Build Tool from here:
# https://scan.coverity.com/download/cxx/linux-64
# Unpack into /vagrant (root of sdn_sensor)

# XXX: Add notes how to run cov-configure on the compiler
../cov-analysis-linux64-*/bin/cov-configure --comptype clangcc --compiler /usr/bin/clang
../cov-analysis-linux64-*/bin/cov-build --dir cov-int make

tar czf sdn_sensor_coverity.tgz cov-int
