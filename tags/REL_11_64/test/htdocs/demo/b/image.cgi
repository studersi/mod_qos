#!/usr/bin/perl -w

use strict;
use CGI;

print "Content-type: image/jpg\r\n";
print "Cache-Control: no-cache, no-store\r\n";
print "\r\n";
my $n = rand(1) * 10 % 10;
my $src = "$n.jpg";

open(DLFILE, "<$src") || Error('open', 'file');
my $record;
my $count=0;
while ($record = <DLFILE>) {
  if($count == 5) {
    sleep 1;
    $count=0;
  }
  $count++;
  print $record;
 }

close (DLFILE) || Error ('close', 'file');
