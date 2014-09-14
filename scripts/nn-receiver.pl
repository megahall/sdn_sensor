#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Cwd qw(abs_path);
use Data::Dumper;
use File::Basename;
use Getopt::Std;
use JSON;
use Scalar::Util qw(looks_like_number);
use Time::HiRes qw(time);
use NanoMsg::Raw;

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

my $parser = JSON->new();

$parser->canonical(1);
$parser->indent(1);
#$parser->indent_length(4);
$parser->relaxed(1);
$parser->space_before(1);
$parser->space_after(1);
$parser->utf8(1);

my $rv;

my $nn_socket = nn_socket(AF_SP, NN_PULL);
die "nn_socket failed: $!" if $nn_socket < 0;

nn_setsockopt($nn_socket, NN_SOL_SOCKET, NN_IPV4ONLY, 0) or die "nn_setsockopt failed: $!";

my $ip_list   = qx(hostname --all-ip-addresses);
my @ip_list   = split(" ", $ip_list);
my @port_list = ( "10001", "10002", "10003", "10004", "10005" );
my @bind_list = ();

foreach my $ip (@ip_list) {
    foreach my $port (@port_list) {
        $rv = nn_bind($nn_socket, "tcp://[$ip]:$port");
        print "ip $ip port $port endpoint $rv\n";
        die "nn_bind failed on [$ip]:$port: $!" if $rv < 0;
        push(@bind_list, $rv);
    }
}

#nn_setsockopt($nn_socket, NN_RCVTIMEO, 1000) or die "nn_setsockopt failed: $!";

my $verbose = 0;

sub handle_sigusr1 {
    my ($sig_name) = @_;
    
    printf("received SIG$sig_name, dumping stack...\n");
    
    my $i = 0;
    while (my @caller = caller($i)) {
        my ($package, $filename, $line, $subroutine) = @caller;
        printf("frame %02d: %s:%s: %s\n", $i++, $filename, $line, $subroutine);
    }
}

$SIG{'USR1'} = \&handle_sigusr1;

my $options = {};
my $options_ok = getopts("v", $options);

die "invalid options provided" unless $options_ok;

$verbose = 1 if $options->{'v'};

my $start;
my $message_id = 0;
my $length = 0;
my $total_length = 0;
my $buffer = "";
my $message;

while (1) {
    $rv = nn_recv($nn_socket, $buffer, 131072, 0);
    last if ($rv == -1);
    $start = time() unless $start;
    
    $length = length($buffer);
    $total_length += $length;
    ++$message_id;
    $message = $parser->decode($buffer);
    print "received callback id $message_id size $length: " . $buffer . "\n" unless $message->{'source'} eq 'pcap';
}

my $stop      = time();
my $elapsed   = $stop - $start;
my $rate      = ($message_id * 1.0) / $elapsed;
my $data      = $total_length / 1_048_576.0;
my $data_rate = $data / $elapsed;

printf("%09d messages in %06.3f secs.\n", $message_id, $elapsed);
printf("%05.3f messages / sec.\n", $rate);
printf("%03.3f MB / sec.\n", $data_rate);

exit(0);
