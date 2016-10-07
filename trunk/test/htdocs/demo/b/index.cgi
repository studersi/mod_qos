#!/usr/bin/perl -w

use strict;
use CGI;

my $cgi = new CGI;
my $method = $ENV{"REQUEST_METHOD"};
my $user = $ENV{"REMOTE_USER"};
my $epoc = time();

print "Content-type: text/html\r\n";
print "Cache-Control: no-cache\r\n";
print "\r\n";
print "<html>\n";
print "<head>\n";
sleep 1;
print "<title>mod_qos demo application B</title>\n";
print "<meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n";
print "<meta name=\"author\" content=\"Pascal Buchbinder\">\n";
print "<meta http-equiv=\"Pragma\" content=\"no-cache, no-store\">\n";
print "<style TYPE=\"text/css\">\n";
print "<!--  \n";
print "  body {\n";
print "	background-color: #AAFFAA;\n";
print "	color: black;\n";
print "	font-family: arial, helvetica, verdana, sans-serif;\n";
print "	font-weight: normal;\n";
print "	text-align: left;\n";
print "  }\n";
print "  a:link    { color: rgb(95,10,15); }\n";
print "  a:visited { color:black; }\n";
print "  a:focus   { color:black; text-decoration:underline; }\n";
print "  a:hover   { color:black; text-decoration:none; }\n";
print "  a:active  { color:black; text-decoration:underline; }\n";
print "-->\n";
print "</style>\n";
print "</head>\n";
sleep 1;
print "<body>\n";
print "\n";
print "<table>\n";
print "<tbody>\n";
print "<tr>\n";
print "<td>\n";
print "    To be, or not to be: that is the question:\n";
print "    Whether 'tis nobler in the mind to suffer\n";
print "    The slings and arrows of outrageous fortune,\n";
print "    Or to take arms against a sea of troubles,\n";
print "    And by opposing end them? To die: to sleep;\n";
print "    No more; and by a sleep to say we end\n";
print "    The heart-ache and the thousand natural shocks\n";
print "    That flesh is heir to, 'tis a consummation\n";
print "    Devoutly to be wish'd. To die, to sleep;\n";
print "    To sleep: perchance to dream: ay, there's the rub;\n";
print "    For in that sleep of death what dreams may come\n";
print "    When we have shuffled off this mortal coil,\n";
print "    Must give us pause: there's the respect\n";
print "    That makes calamity of so long life;\n";
print "    For who would bear the whips and scorns of time,\n";
print "    The oppressor's wrong, the proud man's contumely,\n";
print "    The pangs of despised love, the law's delay,\n";
print "    The insolence of office and the spurns\n";
print "    That patient merit of the unworthy takes,\n";
print "    When he himself might his quietus make\n";
print "    With a bare bodkin? who would fardels bear,\n";
print "    To grunt and sweat under a weary life,\n";
print "    But that the dread of something after death,\n";
print "    The undiscover'd country from whose bourn\n";
print "    No traveller returns, puzzles the will\n";
print "    And makes us rather bear those ills we have\n";
print "    Than fly to others that we know not of?\n";
print "    Thus conscience does make cowards of us all;\n";
print "    And thus the native hue of resolution\n";
print "    Is sicklied o'er with the pale cast of thought,\n";
print "    And enterprises of great pith and moment\n";
print "    With this regard their currents turn awry,\n";
print "    And lose the name of action.--Soft you now!\n";
print "    The fair Ophelia! Nymph, in thy orisons\n";
print "    Be all my sins remember'd.\n";
print "\n";
print "<br><i>William Shakespeare</i>\n";
print "</td>\n";
print "</tr>\n";
print "<tr>\n";
print "<td>\n";
print "<img src=\"image.cgi?id=".$epoc."1\">\n";
print "<img src=\"image.cgi?id=".$epoc."2\">\n";
print "<img src=\"image.cgi?id=".$epoc."3\">\n";
print "<img src=\"image.cgi?id=".$epoc."4\">\n";
print "<img src=\"image.cgi?id=".$epoc."5\">\n";
print "\n";
print "</td>\n";
print "</tr>\n";
print "</tbody>\n";
print "</table>\n";
sleep 1;
print "<p><a href=\"..\">up</a></p>\n";
print "<hr>\n";
print "<a href=\"http://mod-qos.sourceforge.net/\">\n";
print "<SMALL><SMALL>mod_qos</SMALL></SMALL>\n";
print "</a>\n";
print "</body>\n";
print "</html>\n";
