/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */
/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2012 Pascal Buchbinder
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

static const char revision[] = "$Id: qslogger.c,v 1.3 2012-03-30 19:33:10 pbuchbinder Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <regex.h>
#include <syslog.h>

#include "qs_util.h"

// [Wed Mar 28 22:40:41 2012] [warn] 
#define QS_DEFAULTPATTERN "^\\[[0-9a-zA-Z :]+\\] \\[([a-z]+)\\] "

/**
 * Rerurns the priority value
 *
 * @param priorityname
 * @return Priority, LOG_NOTICE if provided name is not recognized.
 */ 
static int qsgetprio(const char *priorityname) {
  int p = LOG_NOTICE;
  if(!priorityname) {
    return p;
  }
  if(strcasestr(priorityname, "alert")) {
    p = LOG_ALERT;
  } else if(strcasestr(priorityname, "crit")) {
    p = LOG_CRIT;
  } else if(strcasestr(priorityname, "debug")) {
    p = LOG_DEBUG;
  } else if(strcasestr(priorityname, "emerg")) {
    p = LOG_EMERG;
  } else if(strcasestr(priorityname, "err")) {
    p = LOG_ERR;
  } else if(strcasestr(priorityname, "info")) {
    p = LOG_INFO;
  } else if(strcasestr(priorityname, "notice")) {
    p = LOG_NOTICE;
  } else if(strcasestr(priorityname, "panic")) {
    p = LOG_EMERG;
  } else if(strcasestr(priorityname, "warn")) {
    p = LOG_WARNING;
  }
  return p;
}

/**
 * Extracts the severity of the message using the provided
 * regular expression and determinest the priofity using
 * qsgetprio().
 *
 * @param preg Regular expression to extract the serverity
 * @param line Log fline to extract the severity from
 * @return Level or LOG_NOTICE if level could not be determined.
 */
static int qsgetlevel(regex_t preg, const char *line) {
  int level = LOG_NOTICE;
  regmatch_t ma[2];
  if(regexec(&preg, line, 1, ma, 0) == 0) {
    level = qsgetprio(&line[ma[1].rm_so]);
  }
  return level;
}

typedef struct {
  const char* name;
  int f;
} qs_f_t;

/**
 * table of known facilities
 */
static const qs_f_t qs_facilities[] = {
    { "authpriv", LOG_AUTHPRIV },
    { "auth", LOG_AUTH },
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "ftp", LOG_FTP },
    { "kern", LOG_KERN },
    { "lpr", LOG_LPR },
    { "mail", LOG_MAIL },
    { "news", LOG_NEWS },
    { "security", LOG_AUTH },
    { "syslog", LOG_SYSLOG },
    { "user", LOG_USER },
    { "uucp", LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
};

/**
 * Determines the facility.
 *
 * @param facilityname
 * @return The facility id or LOG_DAEMON if the provided string is unknown
 */
static int qsgetfacility(const char *facilityname) {
  int f = LOG_DAEMON;
  const qs_f_t *facilities = qs_facilities;
  if(!facilityname) {
    return f;
  }
  while(facilities->name) {
    if(strcasecmp(facilityname, facilities->name) == 0) {
      f = facilities->f;
      break;
    }
    facilities++;
  }
  return f;
}

/**
 * Usage message (or man page)
 *
 * @param cmd
 * @param man
 */
static void usage(const char *cmd, int man) {
  if(man) {
    //.TH [name of program] [section number] [center footer] [left footer] [center header]
    printf(".TH %s 1 \"%s\" \"mod_qos utilities %s\" \"%s man page\"\n", qs_CMD(cmd), man_date,
	   man_version, cmd);
  }
  printf("\n");
  if(man) {
    printf(".SH NAME\n");
  }
  qs_man_print(man, "%s - another shell command interface to the syslog(3) system log module.\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s [-r <expression>] [-t <tag>] [-f <facility>] [-p]\n",  man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "Use this utility to to forward log messages to the systems syslog\n");
  qs_man_print(man, "facility, e.g., to forward the messages to a remote host.\n");
  qs_man_print(man, "It ready data from stdin.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -r <expression>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifies a regular expression which shall be used to\n");
  qs_man_print(man, "     determine the severity (syslog level) for each log line.\n");
  qs_man_print(man, "     The default pattern '"QS_DEFAULTPATTERN"' can\n");
  qs_man_print(man, "     be used for Apache error log messages but you may configure\n");
  qs_man_print(man, "     your own pattern matchin and other log format too. Use brackets\n");
  qs_man_print(man, "     to define the string enclosing the severity string.\n");
  qs_man_print(man, "     Default level (if severity can't be determined) is NOTICE.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -t <tag>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the tag name which shall be used to define the origin\n");
  qs_man_print(man, "     of the messages, e.g. 'httpd'.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -f <facility>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the syslog facility. Default is 'daemon'.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -p\n");
  if(man) printf("\n");
  qs_man_print(man, "     Writes data also to stdout (for piped logging).\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
  } else {
    printf("Example:\n");
  }
  qs_man_println(man, "  ErrorLog \"|./%s -t apache -f local7\"\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qslog(1), qspng(1), qsrotate(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://opensource.adnovum.ch/mod_qos/\n");
  } else {
    printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
  }
  if(man) {
    exit(0);
  } else {
    exit(1);
  }
}

int main(int argc, const char * const argv[]) {
  int line_len;
  char line[MAX_LINE];
  const char *cmd = strrchr(argv[0], '/');
  int pass = 0;
  const char *tag = NULL;
  int facility = LOG_DAEMON;
  int level = LOG_INFO;
  const char *regexpattern = QS_DEFAULTPATTERN;
  regex_t preg;
  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv, "-p") == 0) {
      pass = 1;
    } else if(strcmp(*argv, "-f") == 0) {
      if (--argc >= 1) {
	const char *facilityname = *(++argv);
        facility = qsgetfacility(facilityname);
      }
    } else if(strcmp(*argv, "-t") == 0) {
      if (--argc >= 1) {
	tag = *(++argv);
      }
    } else if(strcmp(*argv, "-r") == 0) {
      if (--argc >= 1) {
	regexpattern = *(++argv);
      }
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    } else {
      usage(cmd, 0);
    }
    argc--;
    argv++;
  }

  if(regcomp(&preg, regexpattern, REG_EXTENDED)) {
    fprintf(stderr, "[%s] failed to compile pattern %s", cmd, regexpattern);
    exit(1);
  }

  openlog(tag ? tag : getlogin(), 0, facility);
  // start reading from stdin
  while(fgets(line, sizeof(line), stdin) != NULL) {
    line_len = strlen(line) - 1;
    while(line_len > 0) { // cut tailing CR/LF
      if(line[line_len] >= ' ') {
	break;
      }
      line[line_len] = '\0';
      line_len--;
    }
    level = qsgetlevel(preg, line);
    syslog(level, "%s", line);
    if(pass) {
      printf("%s\n", line);
    }
  }
  return 0;
}
