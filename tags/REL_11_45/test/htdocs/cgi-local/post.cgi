#!/usr/bin/perl -w

use strict;
use CGI;

my $cgi = new CGI;
my $method = $ENV{"REQUEST_METHOD"};
my $user = $ENV{"REMOTE_USER"};
my $data = $cgi->param( 'POSTDATA' );

print "Content-type: text/plain\r\n";
print "\r\n";
print "Method: ".$method."\n";
print "Body: ".$data."\n";
print "done\n";

