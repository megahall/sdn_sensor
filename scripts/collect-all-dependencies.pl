#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Data::Dumper;
use File::Glob ':bsd_glob';

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

chdir("/var/log");

my @dpkg_logs = glob("dpkg*");
@dpkg_logs = sort { $b cmp $a } (@dpkg_logs);
print Dumper(\@dpkg_logs);

foreach my $dpkg_log_path (@dpkg_logs) {
    open(my $dpkg_log, "<", $dpkg_log_path) || die "could not open dpkg log $dpkg_log_path";
    while (my $line = <$dpkg_log>) {
        chomp($line);
        next unless $line =~ /(.*?) status installed (.*?) /;
        my $timestamp = $1;
        my $package   = $2;
        $package      =~ s/:.*//;
        printf("%-24s%s\n", $timestamp, $package);
    }
    close($dpkg_log);
}

exit(0);


