/**
 *
 * qssyslog.c: syslog traffic generator
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2020 Pascal Buchbinder
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>
#include <string.h>

#include <apr.h>
#include <apr_lib.h>

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

void *usage() {
  printf("\n");
  printf("Usage: qssyslog [-m <total>] [-n <messages/sec>] [-l <length>] [-s <level>] [-f <facility>]\n");
  printf("\n");
  printf("Writes the specified number of log messages to the syslog system log modules.\n");
  printf("\n");
  printf("Options:\n");
  printf(" -m <total>\n");
  printf("    Number of message to create, default is 10.\n");
  printf(" -n <messages/sec>\n");
  printf("    Transmit rate (how many messages per second). Default is 10.\n");
  printf(" -l <length>\n");
  printf("    Message length. Default is 500.\n");
  printf(" -s <level>\n");
  printf("    Level/severity of the message. Default is 'info'\n");
  printf(" -f <facility>\n");
  printf("    Facility to send the message to. Default is 'local3'.\n");
  printf("\n");
  exit(1);
}

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
 * @return Priority, LOG_INFO if provided name is not recognized.
 */
static int qsgetprio(const char *priorityname, int len) {
  int p = LOG_INFO;
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

int main(int argc, char **argv) {
  char *data;
  int max = 10;
  int speed = 1;
  int size = 500;
  int severity = LOG_INFO;
  int facility = LOG_LOCAL3;
  long long duration, start, end, ws, we, sl;
  struct timeval tv;
  int total = 0;
  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-m") == 0) {
      if (--argc >= 1) {
	max = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-n") == 0) {
      if (--argc >= 1) {
	speed = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-l") == 0) {
      if (--argc >= 1) {
	size = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-f") == 0) {
      if (--argc >= 1) {
	const char *f = *(++argv);
	facility = qsgetfacility(f);
      }
    } else if(strcmp(*argv, "-s") == 0) {
      if (--argc >= 1) {
	const char *s = *(++argv);
	severity = qsgetprio(s, strlen(s));
      }
    } else if(strcmp(*argv,"-h") == 0) {
      usage();
    }
    argc--;
    argv++;
  }
  if(size < 12) {
    size = 12;
  }
  if(speed < 10) {
    speed = 10;
  }
  speed = speed / 10 * 10;
  max = max / speed * speed;
  if(max == 0) {
    max = speed;
  }
  printf("start: facility.level=%d.%d lengh=%d number=%d msg/sec=%d\n", 
	 facility, severity, size, max, speed);
  size-=10;
  data = calloc(size+1, 1);
  memset(data, 'Q', size);

  openlog("qssyslog", 0, facility);

  gettimeofday(&tv, NULL);
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  speed = speed / 10; // number of message per 100ms
  while(max > 0) {
    int i;
    gettimeofday(&tv, NULL);
    ws = tv.tv_sec * 1000000 + tv.tv_usec;
    for(i = 0; i < speed; i++) {
      total++;
      syslog(severity, "%.10d%s", total, data);
    }
    max-=speed;
    gettimeofday(&tv, NULL);
    we = tv.tv_sec * 1000000 + tv.tv_usec;
    sl = we - ws;
    // this took "sl" microseconds, wait until we reach 100ms
    sl = sl;
    sl = 100000 - sl;
    if(sl > 0) {
      usleep(sl);
    }
  }
  gettimeofday(&tv, NULL);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  duration = (end - start) / 1000000;
  if(duration == 0) {
    duration = 1;
  }
  printf("end: %d messages (%d per second)\n", total, total / duration);
  return 0;
}
