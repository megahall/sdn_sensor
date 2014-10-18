#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${build_directory}"

# Git settings required for the sdn_sensor repo to work properly
# XXX: git stuff installed as vagrant user, but here we're root
git config --global push.default simple
git config --global fetch.recursesubmodules true
git config --global format.signoff true
git submodule init
git fetch
git submodule update --recursive

cat "${script_directory}/ackrc" > "${HOME}/.ackrc"
cat "${script_directory}/nanorc" > "${HOME}/.nanorc"

echo "running vagrant sudo setup"
sudo "${script_directory}/setup-vagrant-sudo.bash"

echo "running Debian package setup"
sudo "${script_directory}/setup-debian.bash"

echo "running Perl package setup"
sudo "${script_directory}/setup-perl.bash"

echo "running Intel DPDK library setup"
"${script_directory}/setup-dpdk.bash"

echo "running jemalloc library setup"
"${script_directory}/setup-jemalloc.bash"

echo "running nanomsg library setup"
"${script_directory}/setup-nanomsg.bash"

echo "running re2 library setup"
"${script_directory}/setup-re2.bash"

exit 0
