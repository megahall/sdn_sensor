#!/bin/bash

set -e -x

sudo apt-get -y install aptitude

sudo aptitude -y purge command-not-found command-not-found-data python3-commandnotfound ufw

sudo aptitude -y install linux-server linux-headers-server

sudo aptitude -y install gawk strace ltrace telnet netcat-traditional tshark ssh rsync cproto

sudo aptitude -y install libjson-pp-perl libperl6-slurp-perl

sudo aptitude -y install build-essential libc6-dbg clang gdb-multiarch gdb-doc valgrind autoconf automake libtool git git-man manpages-dev manpages-posix-dev

sudo aptitude -y install uthash-dev libbsd-dev libpcre3-dev zlib1g-dev libglib2.0-dev gnulib libjson-c-dev libjson-c-doc liblog4c-dev liblog4c-doc libpcap-dev

# python2.7
# sudo aptitude -y install nginx nginx-extras
