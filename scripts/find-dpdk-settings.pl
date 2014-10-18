#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use File::Glob ':bsd_glob';
use Getopt::Std;

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

sub find_cpu_core_mask {
    my $core_count = qx(nproc --all);
    printf("0x%08d\n", $core_count);
}

sub find_ethernet_pci_ids {
    # /sys/devices/pci0000:00/0000:00:03.0/virtio0
    # /sys/devices/pci0000:00/0000:00:03.0/net/eth0
    chdir("/sys/devices");
    foreach my $ethernet_path (<pci*/*/net/eth*>) {
        # pci0000:00/0000:00:08.0/net/eth0
        # pci0000:00/0000:00:03.0/virtio0
        my ($pci_bus, $pci_id, $junk, $ethernet_id) = split("/", $ethernet_path, 4);
        # goal: virtio0 00:03.0
        $pci_id =~ s/^\d{4}://;
        print "$ethernet_id $pci_id\n";
    }
}

my $options = {};

getopts("cp", $options) or die "invalid options provided: usage: $0 [-c] [-p]";

if ($options->{'c'}) {
    find_cpu_core_mask();
}
elsif ($options->{'p'}) {
    find_ethernet_pci_ids();
}
else {
    die "no options provided: usage: $0 [-c] [-p]";
}

exit(0);
