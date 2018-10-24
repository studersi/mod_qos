/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */
/**
 * Utilities for the quality of service module mod_qos.
 *
 * qslogger.c: Piped logging forwarding log data to syslog
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2018 Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

static const char revision[] = "$Id$";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <regex.h>
#include <syslog.h>

#include <apr.h>
#include <apr_lib.h>

#include "qs_util.h"

// [Wed Mar 28 22:40:41 2012] [warn] 
#define QS_DEFAULTPATTERN "^\\[[0-9a-zA-Z :]+\\] \\[([a-z]+)\\] "

#define QS_MAX_PATTERN_MA 2

static int m_default_severity = LOG_NOTICE;

/**
 * Similar to standard strstr() but case insensitive and lenght limitation
 * (string which is not 0 terminated).
 *
 * @param s1 String to search in
 * @param s2 Pattern to ind
 * @param len Length of s1
 * @return pointer to the beginning of the substring s2 within s1, or NULL
 *         if the substring is not found
 */
static const char *qs_strncasestr(const char *s1, const char *s2, int len) {
  const char *e1 = &s1[len-1];
  char *p1, *p2;
  if (*s2 == '\0') {
    /* an empty s2 */
    return((char *)s1);
  }
  while(1) {
    for ( ; (*s1 != '\0') && (s1 <= e1) && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
    if (*s1 == '\0' || s1 > e1) {
      return(NULL);
    }
    /* found first character of s2, see if the rest matches */
    p1 = (char *)s1;
    p2 = (char *)s2;
    for (++p1, ++p2; (apr_tolower(*p1) == apr_tolower(*p2)) && (p1 <= e1); ++p1, ++p2) {
      if((p1 > e1) && (*p2 != '\0')) {
        // reached the end without match
        return NULL;
      }
      if (*p2 == '\0') {
        /* both strings ended together */
        return((char *)s1);
      }
    }
    if (*p2 == '\0') {
      /* second string ended, a match */
      break;
    }
    /* didn't find a match here, try starting at next character in s1 */
    s1++;
  }
  return((char *)s1);
}

/**
 * Rerurns the priority value
 *
 * @param priorityname Part of the log message to search the priority in
 * @param len Length of the priority string
 * @return Priority, LOG_NOTICE (see m_default_severity) if provided name is not recognized.
 */ 
static int qsgetprio(const char *priorityname, int len) {
  int p = m_default_severity;
  if(!priorityname) {
    return p;
  }
  if(qs_strncasestr(priorityname, "alert", len)) {
    p = LOG_ALERT;
  } else if(qs_strncasestr(priorityname, "crit", len)) {
    p = LOG_CRIT;
  } else if(qs_strncasestr(priorityname, "debug", len)) {
    p = LOG_DEBUG;
  } else if(qs_strncasestr(priorityname, "emerg", len)) {
    p = LOG_EMERG;
  } else if(qs_strncasestr(priorityname, "err", len)) {
    p = LOG_ERR;
  } else if(qs_strncasestr(priorityname, "info", len)) {
    p = LOG_INFO;
  } else if(qs_strncasestr(priorityname, "notice", len)) {
    p = LOG_NOTICE;
  } else if(qs_strncasestr(priorityname, "panic", len)) {
    p = LOG_EMERG;
  } else if(qs_strncasestr(priorityname, "warn", len)) {
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
 * @return Level or LOG_NOTICE (see m_default_severity) if level could not be determined.
 */
static int qsgetlevel(regex_t preg, const char *line) {
  int level = m_default_severity;
  regmatch_t ma[QS_MAX_PATTERN_MA];
  if(regexec(&preg, line, QS_MAX_PATTERN_MA, ma, 0) == 0) {
    int len = ma[1].rm_eo - ma[1].rm_so;
    level = qsgetprio(&line[ma[1].rm_so], len);
  }
  return level;
}

/* entry within the facility table */
typedef struct {
  const char* name;
  int f;
} qs_f_t;

/**
 * Table of known facilities, see sys/syslog.h.
 */
static const qs_f_t qs_facilities[] = {
#ifdef LOG_AUTHPRIV
    { "authpriv", LOG_AUTHPRIV },
#endif
    { "auth", LOG_AUTH },
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
#ifdef LOG_FTP
    { "ftp", LOG_FTP },
#endif
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
 * Determines the facility (user input).
 *
 * @param facilityname
 * @return The facility id or LOG_DAEMON if the provided 
 *         string is unknown.
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
  qs_man_print(man, "%s - another shell command interface to the system log module (syslog).\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s [-t <tag>] [-f <facility>] [-l <level>] [-x <prefix>] [-r <expression>] [-d <level>] [-u <name>] [-p]\n",  man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "Use this utility to forward log messages to the systems syslog\n");
  qs_man_print(man, "facility, e.g., to forward the messages to a remote host.\n");
  qs_man_print(man, "It reads data from stdin.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
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
  qs_man_print(man, "  -u <name>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Becomes another user, e.g. www-data.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -l <level>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the minimal severity a message must have in order to\n");
  qs_man_print(man, "     be forwarded. Default is 'DEBUG' (fowarding everything).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -x <prefix>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Allows you to add a prefix (literal string) to every message.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -r <expression>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifies a regular expression which shall be used to\n");
  qs_man_print(man, "     determine the severity (syslog level) for each log line.\n");
  qs_man_print(man, "     The default pattern '"QS_DEFAULTPATTERN"' can\n");
  qs_man_print(man, "     be used for Apache error log messages but you may configure\n");
  qs_man_print(man, "     your own pattern matching other log formats. Use brackets\n");
  qs_man_print(man, "     to define the pattern enclosing the severity string.\n");
  qs_man_print(man, "     Default level (if severity can't be determined) is defined by the\n");
  qs_man_print(man, "     option '-d' (see below).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -d <level>\n");
  if(man) printf("\n");
  qs_man_print(man, "     The default severity if the specified pattern (-r) does not\n");
  qs_man_print(man, "     match and the message's serverity can't be determined. Default\n");
  qs_man_print(man, "     is 'NOTICE'.\n");
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
  qs_man_println(man, "  ErrorLog \"|/usr/bin/%s -t apache -f local7\"\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qshead(1), qslog(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://mod-qos.sourceforge.net/\n");
  } else {
    printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  }
  if(man) {
    exit(0);
  } else {
    exit(1);
  }
}

int main(int argc, const char * const argv[]) {
  int line_len;
  char *line = calloc(1, MAX_LINE_BUFFER+1);
  const char *cmd = strrchr(argv[0], '/');
  int pass = 0;
  const char *tag = NULL;
  int facility = LOG_DAEMON;
  int severity = LOG_DEBUG;
  int level = LOG_INFO;
  const char *regexpattern = QS_DEFAULTPATTERN;
  const char *username = NULL;
  const char *prefix = NULL;
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
    } else if(strcmp(*argv, "-l") == 0) {
      if (--argc >= 1) {
	const char *severityname = *(++argv);
        severity = qsgetprio(severityname, strlen(severityname));
      }
    } else if(strcmp(*argv, "-x") == 0) {
      if (--argc >= 1) {
	prefix = *(++argv);
      }
    } else if(strcmp(*argv,"-u") == 0) { /* switch user id */
      if (--argc >= 1) {
        username = *(++argv);
      }
    } else if(strcmp(*argv, "-d") == 0) {
      if (--argc >= 1) {
	const char *severityname = *(++argv);
        m_default_severity = qsgetprio(severityname, strlen(severityname));
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

  qs_setuid(username, cmd);

  openlog(tag ? tag : getlogin(), 0, facility);

  // start reading from stdin
  while(fgets(line, MAX_LINE_BUFFER, stdin) != NULL) {
    line_len = strlen(line) - 1;
    while(line_len > 0) { // cut tailing CR/LF
      if(line[line_len] >= ' ') {
	break;
      }
      line[line_len] = '\0';
      line_len--;
    }
    // severity is determined using the regular expression provided by the user
    level = qsgetlevel(preg, line);
    if(level <= severity) {
      // send message
      if(prefix) {
        syslog(level, "%s%s", prefix, line);
      } else {
        syslog(level, "%s", line);
      }
    }
    if(pass) {
      printf("%s\n", line);
      fflush(stdout);
    }
  }
  free(line);
  closelog();
  return 0;
}
