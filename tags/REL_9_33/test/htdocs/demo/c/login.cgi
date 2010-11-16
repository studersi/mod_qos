#!/usr/bin/perl -w

use strict;
use CGI;

print "Content-type: text/html\r\n";
print "Cache-Control: no-cache\r\n";
print "Set-Cookie: SESSIONID=1234567890\r\n";
print "\r\n";
my $n = rand(1) * 10 % 10;
my $src = "index2.html";

open(DLFILE, "<$src") || Error('open', 'file');
my $record;
while ($record = <DLFILE>) {
  print $record;
 }

close (DLFILE) || Error ('close', 'file');

