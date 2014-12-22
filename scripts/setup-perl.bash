#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${script_directory}"

mkdir -p "${HOME}/.cpan/CPAN"
cp "${script_directory}/MyConfig.pm" "${HOME}/.cpan/CPAN/"

sudo aptitude -y install \
makepatch \
perl-doc \
libfile-next-perl \
libterm-readkey-perl libterm-readline-perl-perl \
libcpan-sqlite-perl libmodule-signature-perl \
libjson-perl libjson-pp-perl libjson-xs-perl \
libyaml-libyaml-perl libyaml-perl \
libsocket6-perl libio-socket-inet6-perl libio-socket-ssl-perl \
libwww-perl \
libdigest-hmac-perl libdigest-sha-perl \
libperl6-slurp-perl \
libtest-fatal-perl libtest-sharedfork-perl libtest-tcp-perl \
libgd-perl libgd-graph-perl libyaml-libyaml-perl

cat "${script_directory}/ackrc" > "/home/vagrant/.ackrc"
chown vagrant.vagrant "/home/vagrant/.ackrc"

wget --progress=dot:mega --timestamping http://snapshot.debian.org/archive/debian/20120609T102152Z/pool/main/a/ack-grep/ack-grep_1.96-2_all.deb
sudo dpkg -i ack-grep_1.96-2_all.deb
sudo dpkg-divert --local --divert /usr/bin/ack --rename --add /usr/bin/ack-grep
echo "ack-grep hold" | sudo dpkg --set-selections

# XXX: force-install due to failing UT's
cpan -fi NanoMsg::Raw || true

exit 0
