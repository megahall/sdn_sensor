#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${script_directory}"

sudo aptitude -y install \
python-setuptools \
python-pip \
python-virtualenv \
ipython \
python-ipdb \
python-netaddr
