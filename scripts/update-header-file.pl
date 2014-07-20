#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Data::Dumper;
use File::Basename;
use File::Copy;

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

my $header_path = $ARGV[0];
my $bak_path    = $header_path . ".bak";
my $tmp_path    = $header_path . ".new";
my $code_path   = dirname($header_path) . "/" . basename($header_path, ".h") . ".c";

die "header file $header_path does not exist" unless -f $header_path && $header_path =~ /\.h$/;
die "code file $code_path does not exist"     unless -f $code_path   && $code_path =~ /\.c$/;

my $prototypes = `cproto $code_path`;
my @prototypes = split("\n", $prototypes, -1);
shift(@prototypes);
@prototypes    = map { s/ \*/* /; $_; } (@prototypes);
$prototypes    = join("\n", @prototypes);

my $inside_prototypes = 0;

copy($header_path, $bak_path) or die "could not backup header file: $!";

open(my $header_file, "<", $header_path) or die "could not open header file $header_path";
open(my $tmp_file, ">", $tmp_path) or die "could not open output file $tmp_path";
while (my $line = <$header_file>) {
    chomp($line);
    
    if ($line =~ /END PROTOTYPES/) {
        $inside_prototypes = 0;
        print $tmp_file "$line\n";
    }
    elsif ($inside_prototypes) {
        next;
    }
    elsif ($line =~ /BEGIN PROTOTYPES/) {
        $inside_prototypes = 1;
        print $tmp_file "$line\n";
        print $tmp_file "\n" . $prototypes . "\n";
    }
    else {
        print $tmp_file "$line\n";
    }
}
close($header_file);
close($tmp_file);

move($tmp_path, $header_path) or die "could not update header file: $!";

exit(0);
