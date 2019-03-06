#!/usr/bin/perl -w

use strict;
use CGI;

print "Content-type: text/plain\r\n";
print "Cache-Control: no-cache\r\n";
print "\r\n";

my $i;
my $j;
for($i = 0; $i < 10; $i++) {
  for($j = 0; $j < 800; $j++) {
    print "text text text text text text text text \n";
  }
  sleep 15;
}
print "END\n";

#my $src = "data";
#open(DLFILE, "<$src") || Error('open', 'file');
#my $record;
#my $count=0;
#while ($record = <DLFILE>) {
#  if($count == 100) {
#    sleep 1;
#    $count=0;
#  }
#  $count++;
#  print $record;
# }
#
#close (DLFILE) || Error ('close', 'file');
