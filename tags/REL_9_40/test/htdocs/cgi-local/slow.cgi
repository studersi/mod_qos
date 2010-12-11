#!/usr/bin/perl -w

use strict;
use CGI;

my $cgi = new CGI;
my $method = $ENV{"REQUEST_METHOD"};
my $user = $ENV{"REMOTE_USER"};

# 10 millisec
my $sleep = 0.010;
select (undef, undef, undef, $sleep);

print "Content-type: text/plain\r\n";
print "\r\n";
print "done\n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";
print "long line long line long line long line long line long line long line \n";



