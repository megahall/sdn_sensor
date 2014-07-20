#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Data::Dumper;
use JSON::PP;
use Perl6::Slurp;

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

my $parser = JSON::PP->new();

$parser->canonical(1);
$parser->indent(1);
$parser->indent_length(4);
$parser->relaxed(1);
$parser->space_before(1);
$parser->space_after(1);
$parser->utf8(1);

my $input = slurp \*STDIN;

my $object = $parser->decode($input);

my $output = $parser->encode($object);

print $output . "\n";

exit(0);
