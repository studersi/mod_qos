#!/usr/bin/perl -w

use strict;
use CGI;

print "Content-type: text/html\r\n";
print "Cache-Control: no-cache\r\n";
print "Set-Cookie: SESSIONID=1234567890\r\n";
print "\r\n";

my $cgi = new CGI;
my $name = $cgi->param('name');
my $password = $cgi->param('password');

if($name && $name eq $password) {
  print "<html>\n";
  print "<head><title>Login Successful</title></head>\n";
  print "<body>\n";
  print "<p>Login successful!</p>\n";
  print "</body>\n";
  print "</html>\n";
} else {
  print "<html>\n";
  print "<head><title>Login Failed</title></head>\n";
  print "<body>\n";
  print "<p>Login Failed</p>\n";
  print "<hr>\n";
  print "	Login Form\n";
  print "	<form action=\"login.cgi\" method=\"POST\">\n";
  print "		name: <input name=\"name\" value=\"\"><br>\n";
  print "		password:<input name=\"password\" value=\"\" type=\"password\"><br>\n";
  print "		<input name=\"login\" value=\"login\" type=\"submit\">\n";
  print "	</form>\n";
  print "</body>\n";
  print "</html>\n";
}
