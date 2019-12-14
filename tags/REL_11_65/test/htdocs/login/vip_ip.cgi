#!/usr/bin/perl -w

use strict;
use CGI;

my $cgi = new CGI;

print "Content-type: text/plain\r\n";
print "mod-qos-vip-ip: login\r\n";
print "\r\n";
print "done\n";

