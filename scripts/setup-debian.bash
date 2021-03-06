#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${script_directory}"

function run_aptitude() {
    aptitude --log-file=- --verbose --assume-yes "$@"
}

apt-get -y install aptitude
aptitude update
run_aptitude dist-upgrade

run_aptitude purge command-not-found command-not-found-data python3-commandnotfound ufw
# remove unused SCM clients for performance reasons
run_aptitude purge puppet puppet-common chef chef-zero

run_aptitude install linux-generic linux-headers-generic

run_aptitude install gawk strace ltrace telnet netcat-traditional tshark ssh rsync cproto cscope randomize-lines wamerican-insane sloccount aspell ntp

run_aptitude install build-essential libc6-dbg clang llvm-gcc-4.7 flex bison iwyu gdb-multiarch gdb-doc valgrind autoconf automake libtool mk-configure git git-man git-email subversion manpages-dev manpages-posix-dev doxygen

run_aptitude install uthash-dev libbsd-dev libpcre3-dev zlib1g-dev libglib2.0-dev gnulib libjson-c-dev libjson-c-doc libpcap-dev libfuse-dev libevtlog-dev libgeoip-dev geoip-bin libnet1-dev libvirt-dev

# jemalloc
run_aptitude install libunwind-setjmp0 libunwind-setjmp0-dev libunwind8 libunwind8-dev liblzma-dev docbook-xml docbook-xsl sgml-data xsltproc

# python2.7
# run_aptitude install nginx nginx-extras

#run_aptitude clean
