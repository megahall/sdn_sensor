#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${script_directory}"

cat > /etc/hosts <<'EOF'
# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

127.0.0.1 sdn-sensor
EOF

hostname sdn-sensor

cat "${script_directory}/ackrc" > "/home/vagrant/.ackrc"
cat "${script_directory}/inputrc" > "/etc/inputrc"
cat "${script_directory}/sources.list" > "/etc/apt/sources.list"

apt-get -y install aptitude
aptitude update
aptitude dist-upgrade

# remove unused SCM clients for performance reasons
aptitude purge puppet puppet-common chef chef-zero

aptitude -y purge command-not-found command-not-found-data python3-commandnotfound ufw

aptitude -y install linux-server linux-headers-server

aptitude -y install gawk strace ltrace telnet netcat-traditional tshark ssh rsync cproto cscope

aptitude -y install libjson-pp-perl libperl6-slurp-perl libdigest-sha-perl libfile-next-perl

aptitude -y install build-essential libc6-dbg clang llvm-gcc-4.7 flex bison iwyu gdb-multiarch gdb-doc valgrind autoconf automake libtool git git-man git-email subversion manpages-dev manpages-posix-dev

aptitude -y install uthash-dev libbsd-dev libpcre3-dev zlib1g-dev libglib2.0-dev gnulib libjson-c-dev libjson-c-doc liblog4c-dev liblog4c-doc libpcap-dev libfuse-dev libevtlog-dev libgeoip-dev geoip-bin libnet1-dev

# jemalloc
aptitude -y install libunwind-setjmp0 libunwind-setjmp0-dev libunwind8 libunwind8-dev docbook-xml docbook-xsl sgml-data xsltproc

wget --timestamping http://snapshot.debian.org/archive/debian/20120609T102152Z/pool/main/a/ack-grep/ack-grep_1.96-2_all.deb
dpkg -i ack-grep_1.96-2_all.deb
dpkg-divert --local --divert /usr/bin/ack --rename --add /usr/bin/ack-grep
echo "ack-grep hold" | dpkg --set-selections

# python2.7
# aptitude -y install nginx nginx-extras

#aptitude clean
