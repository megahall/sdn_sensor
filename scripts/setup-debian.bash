#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f $BASH_SOURCE))"
source "${script_directory}/../sdn_sensor_rc"
cd "${script_directory}"

apt-get -y install aptitude
aptitude update
aptitude -y dist-upgrade

aptitude -y purge command-not-found command-not-found-data python3-commandnotfound ufw
# remove unused SCM clients for performance reasons
aptitude -y purge puppet puppet-common chef chef-zero

aptitude -y install linux-generic linux-headers-generic

aptitude -y install gawk strace ltrace telnet netcat-traditional tshark ssh rsync cproto cscope

aptitude -y install build-essential libc6-dbg clang llvm-gcc-4.7 flex bison iwyu gdb-multiarch gdb-doc valgrind autoconf automake libtool git git-man git-email subversion manpages-dev manpages-posix-dev

aptitude -y install uthash-dev libbsd-dev libpcre3-dev zlib1g-dev libglib2.0-dev gnulib libjson-c-dev libjson-c-doc liblog4c-dev liblog4c-doc libpcap-dev libfuse-dev libevtlog-dev libgeoip-dev geoip-bin libnet1-dev

# jemalloc
aptitude -y install libunwind-setjmp0 libunwind-setjmp0-dev libunwind8 libunwind8-dev docbook-xml docbook-xsl sgml-data xsltproc

# python2.7
# aptitude -y install nginx nginx-extras

#aptitude clean
