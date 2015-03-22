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

my $interrupted = 0;

my $rv;

my $nn_socket = nn_socket(AF_SP, NN_PUSH);
die "nn_socket failed: $!" if $nn_socket < 0;

#nn_setsockopt($nn_socket, NN_SOL_SOCKET, NN_IPV4ONLY, 0) or die "nn_setsockopt failed: $!";

my @buffers = (
    '{ "source": "pcap", "rule": "http_get_request", "seq_num": 1, "port_id": 0, "direction": "RX", "self": 0, "length": 995, "eth_type": 2048, "smac": "c8:e0:eb:17:5b:39", "dmac": "78:96:84:71:ea:c0", "sip": "192.168.1.77", "dip": "54.172.186.61", "ip_protocol": 6, "ttl": 0, "l4_length": 941, "icmp_type": 255, "icmp_code": 255, "sport": 51562, "dport": 80, "dns_name": "" }',
    '{ "source": "pcap", "rule": "http_get_request", "seq_num": 2, "port_id": 0, "direction": "RX", "self": 0, "length": 553, "eth_type": 2048, "smac": "78:96:84:71:ea:c0", "dmac": "c8:e0:eb:17:5b:39", "sip": "54.172.186.61", "dip": "192.168.1.77", "ip_protocol": 6, "ttl": 0, "l4_length": 499, "icmp_type": 255, "icmp_code": 255, "sport": 80, "dport": 51562, "dns_name": "" }',
    '{ "source": "frame_ioc", "seq_num": 1, "port_id": 0, "direction": "RX", "self": 0, "length": 98, "eth_type": 2048, "smac": "c8:e0:eb:17:5b:39", "dmac": "78:96:84:71:ea:c0", "sip": "192.168.1.77", "dip": "66.55.144.180", "ip_protocol": 1, "ttl": 0, "l4_length": 56, "icmp_type": 8, "icmp_code": 0, "sport": 0, "dport": 0, "dns_name": "", "file_id": 0, "ioc_id": 106231730, "type": "IP", "threat_type": "bot_ip", "ip": "66.55.144.180", "value": "66.55.144.180", "dns": "" }',
);

#my $ip_list   = qx(hostname --all-ip-addresses);
#my @ip_list   = split(" ", $ip_list);
my @ip_list = "127.0.0.1";
#unshift(@ip_list, "127.0.0.1");
my @port_list = ( "31337" );
my @connect_list = ();

foreach my $ip (@ip_list) {
    foreach my $port (@port_list) {
        my $url = "tcp://[$ip]:$port";
        print "attempt connect, url: $url\n";
        $rv = nn_connect($nn_socket, $url);
        print "connect completed, url: $url\n";
        print "ip $ip port $port endpoint $rv\n";
        die "nn_connect failed on [$ip]:$port: $!" if $rv < 0;
        push(@connect_list, $rv);
    }
}

#nn_setsockopt($nn_socket, NN_RCVTIMEO, 1000) or die "nn_setsockopt failed: $!";

my $verbose = 0;

sub handle_sigint {
    $interrupted = 1;
}

sub handle_sigusr1 {
    my ($sig_name) = @_;
    
    printf("received SIG$sig_name, dumping stack...\n");
    
    my $i = 0;
    while (my @caller = caller($i)) {
        my ($package, $filename, $line, $subroutine) = @caller;
        printf("frame %02d: %s:%s: %s\n", $i++, $filename, $line, $subroutine);
    }
}

$SIG{'INT'} = \&handle_sigint;
$SIG{'USR1'} = \&handle_sigusr1;

my $options = {};
my $options_ok = getopts("v", $options);

die "invalid options provided" unless $options_ok;

$verbose = 1 if $options->{'v'};

my $start;
my $message_id = 0;
my $length = 0;
my $total_length = 0;

while (!$interrupted) {
    foreach my $buffer (@buffers) {
        $rv = nn_send($nn_socket, $buffer);
        #last if ($rv == -1);
        $start = time() unless $start;
        
        $length = length($buffer);
        $total_length += $length;
        ++$message_id;
        print "sent message id $message_id\n";
        sleep(1) unless $interrupted;
    }
}

my $stop      = time();
my $elapsed   = $stop - $start;
my $rate      = ($message_id * 1.0) / $elapsed;
my $data      = $total_length / 1_048_576.0;
my $data_rate = $data / $elapsed;

printf("%09d messages in %06.3f secs.\n", $message_id, $elapsed);
printf("%05.3f messages / sec.\n", $rate);
printf("%03.3f MB / sec.\n", $data_rate);

# follow POSIX SIGINT handler rules
if ($interrupted) {
    kill("SIGINT", $$);
}
else {
    exit(0);
}
