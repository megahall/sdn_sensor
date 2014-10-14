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

sub find_virtio_pci_ids {
    # /sys/devices/pci0000:00/0000:00:03.0/virtio0
    # /sys/devices/pci0000:00/0000:00:08.0/virtio1
    chdir("/sys/devices");
    foreach my $virtio_path (<pci*/*/virtio*>) {
        # pci0000:00/0000:00:03.0/virtio0
        my ($pci_bus, $pci_id, $virtio_id) = split("/", $virtio_path, 3);
        # goal: virtio0 00:03.0
        $pci_id =~ s/^\d{4}://;
        print "$virtio_id $pci_id\n";
    }
}

my $options = {};

getopts("cv", $options) or die "invalid options provided: usage: $0 [-c] [-v]";

if ($options->{'c'}) {
    find_cpu_core_mask();
}
elsif ($options->{'v'}) {
    find_virtio_pci_ids();
}
else {
    die "no options provided: usage: $0 [-c] [-v]";
}

exit(0);
