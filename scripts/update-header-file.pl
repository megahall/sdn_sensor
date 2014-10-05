#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Data::Dumper;
use Digest::SHA qw(sha1_hex);
use File::Basename;
use File::Copy;
use Perl6::Slurp;

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

sub check_header_file {
    my ($header_path) = @_;
    my $bak_path      = $header_path . ".bak";
    my $tmp_path      = $header_path . ".new";
    my $code_path     = dirname($header_path) . "/" . basename($header_path, ".h") . ".c";
    
    die "header file $header_path does not exist" unless -f $header_path && $header_path =~ /\.h$/;
    die "code file $code_path does not exist"     unless -f $code_path   && $code_path =~ /\.c$/;
    
    return {
        'header_path' => $header_path,
        'bak_path'    => $bak_path,
        'tmp_path'    => $tmp_path,
        'code_path'   => $code_path,
    };
}

sub update_prototypes {
    my ($h) = @_;
    my $prototypes = `cproto $h->{'cproto_options'} $h->{'code_path'}`;
    die "header file $h->{'header_path'} did not compile" if $?;
    my @prototypes = split("\n", $prototypes, -1);
    shift(@prototypes);
    @prototypes    = map { s/ \*/* /g; $_; } (@prototypes);
    $prototypes    = join("\n", @prototypes);
    
    my $inside_prototypes = 0;
    
    open(my $header_file, "<", $h->{'header_path'}) or die "could not open header file $h->{'header_path'}";
    open(my $tmp_file, ">", $h->{'tmp_path'}) or die "could not open output file $h->{'tmp_path'}";
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
}

my @file_list   = ();
my @option_list = ();
while (@ARGV) {
    my $parameter = shift(@ARGV);
    if ($parameter eq '--') {
        # all other items are file names
        # loop over them in Perl
        push(@file_list, @ARGV);
        last;
    }
    elsif ($parameter =~ /^-/) {
        # option: pass it to cproto
        push(@option_list, $parameter);
    }
    else {
        # file name: loop over it in Perl
        push(@file_list, $parameter);
    }
}

my $cproto_options = join(" ", @option_list);

#print "fl:\n" . Dumper(\@file_list);
#print "ol:\n" . Dumper(\@option_list);
#print "co: " . $cproto_options . "\n";

foreach my $header_path (@file_list) {
    my $h = check_header_file($header_path);
    $h->{'cproto_options'} = $cproto_options;
    
    copy($h->{'header_path'}, $h->{'bak_path'}) or die "could not backup header file: $!";
    
    update_prototypes($h);
    
    my $header_data = slurp($h->{'header_path'});
    my $tmp_data    = slurp($h->{'tmp_path'});
    my $header_sha1 = sha1_hex($header_data);
    my $tmp_sha1    = sha1_hex($tmp_data);
    if ($header_sha1 eq $tmp_sha1) {
        print "skipping unchanged header $h->{'header_path'}\n";
        my $rv = unlink($h->{'bak_path'}, $h->{'tmp_path'});
    }
    else {
        move($h->{'tmp_path'}, $h->{'header_path'}) or die "could not update header file: $!";
    }
}

exit(0);
