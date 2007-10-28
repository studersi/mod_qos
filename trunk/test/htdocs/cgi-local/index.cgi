#!/usr/bin/perl -w

use strict;
use CGI;

my $cgi = new CGI;
my $method = $ENV{"REQUEST_METHOD"};
my $user = $ENV{"REMOTE_USER"};
my $s = $cgi->param('s');

print "Content-type: text/plain\r\n";
print "\r\n";
print "done\n";

print "\n\nHTTP Headers:\n";
foreach my $key (sort keys %ENV) {
  if(index($key,"HTTP_") != -1) {
    print " ".$key.": ".$ENV{$key}."\n";
  }
}

if($method eq "POST") {
  my $upload_filehandle = $cgi->upload("filepath");
  print ". $upload_filehandle\n";
}

