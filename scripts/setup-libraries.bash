#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${build_directory}"

echo "running nanomsg library setup"
"${script_directory}/setup-nanomsg.bash"

echo "running Perl package setup"
sudo "${script_directory}/setup-perl.bash"

echo "running Python package setup"
sudo "${script_directory}/setup-python.bash"

echo "running jemalloc library setup"
"${script_directory}/setup-jemalloc.bash"

echo "running re2 library setup"
"${script_directory}/setup-re2.bash"

echo "running spcdns library setup"
"${script_directory}/setup-spcdns.bash"

echo "running liblmdb library setup"
"${script_directory}/setup-lmdb.bash"

echo "dependency library setup completed"
exit 0
