#!/usr/bin/perl -w

use strict;
use CGI;

print "Content-type: image/gif\r\n";
print "\r\n";
my $src = "../mod_qos_s.gif";

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
