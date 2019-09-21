#!/usr/bin/perl -w

use strict;
use IO::Socket::INET;
use IO::Socket::SSL;
use Getopt::Long;
use threads;
use threads::shared;

my $server = "127.0.0.1";
my $port = 5002;
my $ssl = 1;

sub doconnections {
    my $num = 2;
    my $primarypayload =
	"GET / HTTP/1.1\r\n"
	. "Host: $server\r\n"
	. "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)\r\n";

    my @sock;
    for(my $j = 1; $j <= $num; $j++) {
	if($ssl == 1) {
	    $sock[$j] = new IO::Socket::SSL(
		PeerAddr => $server,
		PeerPort => $port,
		Timeout  => 100,
		Proto    => "tcp",
		SSL_verify_mode => SSL_VERIFY_NONE,
		) or die "failed connect to $server:$port, " . &IO::Socket::SSL::errstr . "\n";
	} else {
	    $sock[$j] = new IO::Socket::INET(
		PeerAddr => $server,
		PeerPort => $port,
		Timeout  => 100,
		Proto    => "tcp",
		) or die "failed connect to $server:$port\n";
	}
	my $h = $sock[$j];
	print $h $primarypayload;
    }
    for(my $j = 1; $j < $num; $j++) {
	my $h = $sock[$j];
#	for(my $i = 0; $i < 2; $i++) {
#	    sleep(1);
#	    print $h "X-hdr: a\r\n";
#	}
	print $h "\r\n";
	print $h "1234567890123456789012345678901234567890AA";
    }
}

my @thrs;
for(my $k = 0; $k < 2; $k++ ) {
    $thrs[$k] = threads->create(\&doconnections);
}
foreach my $thr (@thrs) {
    print ".";
    $thr->join();
}
print "\n";
