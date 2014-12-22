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
echo "sdn-sensor" > /etc/hostname

ipv6_active=$(grep inet6 /etc/network/interfaces /etc/network/interfaces.d/* || true)
if [[ -z $ipv6_active ]]; then
    echo "iface eth0 inet6 auto" >> "/etc/network/interfaces.d/eth0.cfg"
fi

sed -i \
-e 's/^net\.ipv6\.conf\.all\.use_tempaddr.*/net.ipv6.conf.all.use_tempaddr = 0/g' \
-e 's/^net\.ipv6\.conf\.default\.use_tempaddr.*/net.ipv6.conf.default.use_tempaddr = 0/g' \
/etc/sysctl.d/10-ipv6-privacy.conf
sysctl -p /etc/sysctl.d/10-ipv6-privacy.conf

cat "${script_directory}/inputrc" > "/etc/inputrc"
cat "${script_directory}/sources.list" > "/etc/apt/sources.list"
sed -i -e 's/^color ,green/#color ,green/' /usr/share/nano/*.nanorc

sed -i \
-e 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="hugepages=64"/' \
-e 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="hugepages=64"/' \
/etc/default/grub
update-grub

found_hugetlbfs=$(grep "/hugetlbfs" /etc/fstab || true)
if [[ -z ${found_hugetlbfs} ]]; then
    echo "nodev           /hugetlbfs      hugetlbfs defaults        0       0" >> /etc/fstab
fi

if [[ ! -e "/hugetlbfs" ]]; then
    mkdir /hugetlbfs
    mount /hugetlbfs
fi

found_uio=$(egrep "^uio" /etc/modules || true)
if [[ -z ${found_uio} ]]; then
    echo "uio" >> /etc/modules
    echo "igb_uio" >> /etc/modules
fi
