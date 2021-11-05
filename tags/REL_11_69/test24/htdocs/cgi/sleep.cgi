#!/usr/bin/perl -w

use strict;
use CGI;

my $cgi = new CGI;
my $method = $ENV{"REQUEST_METHOD"};
my $user = $ENV{"REMOTE_USER"};
my $s = $cgi->param('s');
my $l = $cgi->param('l');

if($s) {
  sleep $s;
} else {
  sleep 3;
}

print "Content-type: text/plain\r\n";
print "\r\n";
print "done\n";
if($l) {
    for(my $i = 0; $i < $l; $i++) {
	print "data data data data data data data data data data data data\n";
    }
}
