#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Cwd qw(abs_path);
use Data::Dumper;
use File::Basename;
use Getopt::Std;
use GD;
use GD::Graph::bars;
use IO::File;
use IO::Handle;
use IO::Socket::INET;
use List::Util qw(max min);
use NanoMsg::Raw;
use POSIX qw(asctime ctime gmtime localtime);
use Scalar::Util qw(looks_like_number);
use Time::HiRes qw(time);
use YAML::XS;

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

STDOUT->binmode(":utf8");
STDOUT->autoflush(1);

my $script_directory = dirname(abs_path($0));

my $nn_mode = 0;

my $options = {};
my $options_ok = getopts("n", $options);
die "invalid options provided" unless $options_ok;

$nn_mode = 1 if $options->{'n'};

my $message_count = 0;
my $message_size = 0;
my $start = time();

my $buffer;
my $length;
my $socket;
my $rv;

my $platform = qx(uname -s);
chomp($platform);
if ($platform eq 'Darwin') {
    print "entering working directory...\n";
    chdir("/Library/WebServer/Documents/charts");
}

if ($nn_mode) {
    $socket = nn_socket(AF_SP, NN_PULL);
    die "could not open nn_socket: " . nn_strerror(nn_errno()) if $socket < 0;
    $rv = nn_bind($socket, "tcp://0.0.0.0:31338");
    die "could not bind nn_socket: " . nn_strerror(nn_errno()) if $rv < 0;
}
else {
    $socket = IO::Socket::INET->new('Proto' => 'udp', 'LocalAddr' => '0.0.0.0', 'LocalPort' => 31338) or die "could not open socket: $!";
    $socket->setsockopt(SOL_SOCKET, SO_RCVBUF, 262144) or die "could not set SO_RCVBUF: $!";
}

my $log    = IO::File->new("reports.txt", "w") or die "could not open log: $!";
$log->binmode(":utf8");
$log->autoflush(1);

my $slog    = IO::File->new("sessions.txt", "w") or die "could not open log: $!";
$slog->binmode(":utf8");
$slog->autoflush(1);

my $rlog    = IO::File->new("reputation.txt", "w") or die "could not open log: $!";
$rlog->binmode(":utf8");
$rlog->autoflush(1);

my $y_regexes = [ qr/bytes/i, qr/sessions/i, qr/count/i ];

sub lprint {
    my ($string) = @_;
    print $string;
    print $log $string;
}

sub sprint {
    my ($string) = @_;
    #print $string;
    print $slog $string;
}

sub rprint {
    my ($string) = @_;
    #print $string;
    print $rlog $string;
}

sub check_name {
    my ($y_name) = @_;
    foreach my $y_regex (@$y_regexes) {
        return 1 if $y_name =~ $y_regex;
    }
    return 0;
}

sub calculate_ikey {
    my ($l) = @_;
    my @ikey = ($l->{'source'}, $l->{'type'}, $l->{'value'}, $l->{'threat_type'}, $l->{'type'}, 'ID ' . $l->{'ioc_id'}, 'SEV ' . 'Unknown');
    my $ikey = join(' ', grep { defined($_); } @ikey);
    return $ikey;
}

while (1) {
    $buffer = "";
    if ($nn_mode) {
        $rv = nn_recv($socket, $buffer, 131072);
        if ($rv <= 0) {
            die "nn_recv error: " . nn_strerror(nn_errno());
        }
    }
    else {
        $socket->recv($buffer, 65536);
    }
    $length = length($buffer);
    die "could not read payload: $!" unless $length > 0;
    $message_count += 1;
    $message_size  += $length;
    
    my $report;
    eval {
        $report = YAML::XS::Load($buffer);
    };
    if ($@) {
        lprint "warning: YAML parse error: $@";
        #lprint Dumper($buffer);
        next;
    }
    my $timestamp = $report->{'time'};
    my $id        = $report->{'id'};
    my $statement = $report->{'statement'};
    
    #print Dumper($report);
    my $output    = "$statement.png";
    my $entries   = $report->{'entries'};
    
    if ($statement eq "MatchPatternCorrelation") {
        foreach my $match (@{$report->{'entries'}}) {
            my $first   = $match->{'first_event'};
            my $last    = $match->{'last_event'};
            my $count   = $match->{'repeat_count'};
            my $ikey    = $last ? calculate_ikey($last) : "Unknown";
            
            my $stime   = $first->{'time'};
            my $sts     = $stime ? $stime : "Unknown";
            my $key     = $first->{'hash_key'};
            $key        =~ s/\x1F/ /g;
            
            my $etime   = $last ? $last->{'time'} : $report->{'time'};
            #my $elapsed = $last ? $last->{'elapsed'} : ($etime - $stime) / 1000;
            my $ets     = $etime? $etime : "Unknown";
            
            my $sm = "";
            $sm .= "Context expired hash key [$key] repeat_count [$count]:\n";
            $sm .= "    start   $sts\n";
            $sm .= "    end     $ets\n";
            #$sm .= "    elapsed $elapsed secs.\n";
            $sm .= "    skey    $key\n";
            $sm .= "    ikey    $ikey\n";
            sprint $sm;
        }
        next;
    }
    elsif ($statement eq "ReputationCorrelation") {
        foreach my $match (@{$report->{'entries'}}) {
            my $lm      = $match->{'lm'};
            my $conn    = $match->{'conn'};
            my $mconn   = $match->{'mconn'};
            
            my $stime   = $lm->{'timeGenerated'};
            my $sts     = $stime ? $stime : "Unknown";
            my $sid     = $lm->{'sessionid'};
            my $key     = $lm->{'hash_key'};
            $key        =~ s/\x1F/ /g;
            my $src     = $lm->{'src'};
            
            my $ckey    = $conn->{'hash_key'} || "";
            $ckey       =~ s/\x1F/ /g;
            
            my $type    = $mconn->{'reportType'} || "";
            my $comment = $mconn->{'comment'} || "";
            my $cidr    = $mconn->{'dstIp'} || "";
            my $mkey    = $mconn->{'hash_key'} || "";
            $mkey       =~ s/\x1F/ /g;
            
            my $ikey    = $lm->{'type'} eq 'THREAT' ? calculate_ikey($lm) : "";
            my $url     = $lm->{'misc'} || "";
            
            rprint "Conn Table detected reputation based threat from [$src]:\n";
            rprint "    time    $sts\n";
            rprint "    type    $type\n" if $type;
            rprint "    cidr    $cidr\n" if $cidr;
            rprint "    comment $comment\n" if $comment;
            rprint "    skey    $key\n";
            rprint "    ikey    $ikey\n" if $ikey;
            rprint "    mkey    $mkey\n" if $mkey;
            rprint "    ckey    $ckey\n" if $ckey;
            rprint "    url     $url\n" if $url;
        }
        next;
    }
    
    lprint "report type [$statement] id [$id] count [$message_count] at time [$timestamp]\n";
    
    if ($statement !~ m/Top$/) {
        lprint "skipping event type [$statement]:\n";
        lprint $buffer;
        next;
    }
    
    my $XL;
    my $XV = [];
    my $YV = [];
    
    foreach my $entry (@$entries) {
        while ((my $K, my $V) = each(%$entry)) {
            if (check_name($K)) {
                #print "retrieve Y $V\n";
                push(@$YV, $V);
            }
            elsif ($K ne 'vsys' && $K ne 'threatid') {
                my $entry_XV;
                if ($entry->{'threatid'}) {
                    $entry_XV = "IP $V Threat " . $entry->{'threatid'};
                }
                elsif ($entry->{'entry'}) {
                    $entry_XV = $entry->{'entry'};
                    #$entry_XV =~ s/\?.*//;
                    $entry_XV =~ s%/.*%%;
                    #print "fixed XV: $entry_XV\n";
                }
                else {
                    $entry_XV = $V;
                }
                #print "retrieve X $V\n";
                push(@$XV, $entry_XV);
                $XL = uc($K);
            }
        }
    }
    
    #print Dumper($XL, $XV, $YV);
    
    unless (@$XV && @$YV) {
        lprint "broken report id [$id] type [$statement] at time [$timestamp]\n";
        next;
    }
    
    my $y_min = min(@$YV) * 0.90;
    my $y_max = max(@$YV) * 1.05;
    
    lprint "generate report id [$id] type [$statement] at time [$timestamp] in output file [$output]\n";
    
    my $chart = GD::Graph::bars->new(1024, 768);
    
    $chart->set(
        'title'             => "$statement at $timestamp",
        'x_label'           => $XL,
        'x_labels_vertical' => 1,
        'y_label'           => "Data Value",
        'y_min_value'       => $y_min,
        'y_max_value'       => $y_max,
        'y_tick_number'     => 10,
        'bar_spacing'       => 10,
        'transparent'       => 0,
        'bgclr'             => 'white',
        'dclrs'             => [ 'dblue' ],
    );
    
    $chart->set_text_clr("black");
    #print "TTF mode: " . ($chart->can_do_ttf() ? "true" : "false") . "\n";
    $chart->set_title_font("$script_directory/fonts/DejaVuLGCSansMono.ttf", 18);
    $chart->set_x_label_font("$script_directory/fonts/DejaVuLGCSansMono.ttf", 12);
    $chart->set_x_axis_font("$script_directory/fonts/DejaVuLGCSansMono.ttf", 10);
    $chart->set_y_label_font("$script_directory/fonts/DejaVuLGCSansMono.ttf", 12);
    $chart->set_y_axis_font("$script_directory/fonts/DejaVuLGCSansMono.ttf", 10);
    #$chart->set_bg_clr("white");
    
    my $data = [
        $XV,
        $YV,
    ];

    my $output_gd = $chart->plot($data) or die $chart->error;
    
    open(my $output_file, ">", $output) or die "could not open output file: $!";
    print $output_file $output_gd->png();
    close($output_file);
}
    
#    next unless $message_count % 1_000 == 0;
#    
#    my $current   = time();
#    my $elapsed   = $current - $start;
#    my $rate      = ($message_count * 1.0) / $elapsed;
#    my $data      = $message_size / 1_048_576.0;
#    my $data_rate = $data / $elapsed;
#    
#    printf("%09d messages in %06.3f secs.\n", $message_count, $elapsed);
#    printf("%05.3f messages / sec.\n", $rate);
#    printf("%03.3f MB / sec.\n", $data_rate);

close($socket);

exit(0);
