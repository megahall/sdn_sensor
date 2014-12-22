#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${build_directory}"

cat "${script_directory}/ackrc" > "${HOME}/.ackrc"
cat "${script_directory}/nanorc" > "${HOME}/.nanorc"
mkdir -p "${HOME}/.ssh"
cat "${script_directory}/ssh_config" > "${HOME}/.ssh/config"

echo "running vagrant sudo setup"
sudo "${script_directory}/setup-vagrant-sudo.bash"

echo "running Debian package setup"
sudo "${script_directory}/setup-debian.bash"

# Git settings required for the sdn_sensor repo to work properly
# Git must be installed first before the steps will succeed
git config --global push.default simple
git config --global fetch.recursesubmodules true
git config --global format.signoff true
git submodule init
git fetch
git submodule update --recursive

echo "running dependency library setup"
sudo "${script_directory}/setup-libraries.bash"

echo "vagrant phase 1 setup completed"
exit 0
