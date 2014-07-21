#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Data::Dumper;
use File::Basename;

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

my $header_path  = $ARGV[0];
my $header_fname = basename($header_path, ".h");

die "header file $header_path already exists" if -f $header_path;

open(my $header_file, ">", $header_path) or die "could not open header file $header_path";

my $macro_name = uc($header_fname);

print $header_file <<EOF;
#ifndef __${macro_name}_H__
#define __${macro_name}_H__


/* BEGIN PROTOTYPES */



/* END PROTOTYPES */

#endif /* __${macro_name}_H__ */
EOF

exit(0);
