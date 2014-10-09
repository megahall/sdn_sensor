#!/bin/bash

set -e -x

script_directory=$(dirname $(readlink -f $BASH_SOURCE))

echo "running Debian package setup"
"${script_directory}/setup-debian.bash"

echo "running jemalloc library setup"
"${script_directory}/setup-jemalloc.bash"

echo "running nanomsg library setup"
"${script_directory}/setup-nanomsg.bash"

echo "running re2 library setup"
"${script_directory}/setup-re2.bash"

exit 0
