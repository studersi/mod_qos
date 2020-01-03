/**
 * qssearch.c: searches log data for a pattern
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

static const char revision[] = "$Id$";

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <pcre.h>

/* apr */
#include <apr.h>
#include <apr_uri.h>
#include <apr_signal.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_support.h>
#include <apr_base64.h>

static void usage(char *cmd, int man) {

  printf("%s%s -h <hours> -p <pattern> [-t <type>]\n",
	 man ? "" : "Usage: ", cmd);
  if(man) {
    exit(0);
  } else {
    exit(1);
  }
}

#define TMSRTLEN 128

/**
 * Creates the time pattern type 1 resp 2 accordin to qs_calc_regex()
 * for the current time minus the specified offset
 *
 * @param pool
 * @param offset Time offset in hours
 * @return Pattern to match the log longes for the defined time (hour) only
 */
static char *qs_time_t12(apr_pool_t *pool, int offset) {
  time_t tm = time(NULL);
  struct tm *ptr;
  char *time_string = apr_pcalloc(pool, TMSRTLEN);
  tm -= (offset * 3600);
  ptr = localtime(&tm);
  strftime(time_string, TMSRTLEN,
	   "(%Y[ -]%m[ -]%d %H:)", ptr);
  return time_string;
}

/**
 * Creates the time pattern type 3 accordin to qs_calc_regex()
 * for the current time minus the specified offset
 *
 * @param pool
 * @param offset Time offset in hours
 * @return Pattern to match the log longes for the defined time (hour) only
 */
static char *qs_time_t3(apr_pool_t *pool, int offset) {
  time_t tm = time(NULL);
  struct tm *ptr;
  char *time_string = apr_pcalloc(pool, TMSRTLEN);
  tm -= (offset * 3600);
  ptr = localtime(&tm);
  strftime(time_string, TMSRTLEN,
	   "(%a %b %d %H:[0-9]{2}:[0-9]{2} %Y)", ptr);
  return time_string;
}

/**
 * Creates the time pattern type 4 accordin to qs_calc_regex()
 * for the current time minus the specified offset
 *
 * @param pool
 * @param offset Time offset in hours
 * @return Pattern to match the log longes for the defined time (hour) only
 */
static char *qs_time_t4(apr_pool_t *pool, int offset) {
  time_t tm = time(NULL);
  struct tm *ptr;
  char *time_string = apr_pcalloc(pool, TMSRTLEN);
  tm -= (offset * 3600);
  ptr = localtime(&tm);
  strftime(time_string, TMSRTLEN,
	   "(%d/%b/%Y:%H:)", ptr);
  return time_string;
}

/**
 * Determines tha date format using the first log line
 *
 * @param pool
 * @param line log line
 * @retrun type (or 0 if unknown)
 */
static int qs_get_type(apr_pool_t *pool, const char *line) {
  const char *errptr = NULL;
  int erroffset;
  pcre *preg;
  preg = pcre_compile("^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
		      0, &errptr, &erroffset, NULL);
  if(pcre_exec(preg, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0) {
    return 1;
  }
  preg = pcre_compile("^[0-9]{4} [0-9]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
		      0, &errptr, &erroffset, NULL);
  if(pcre_exec(preg, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0) {
    return 2;
  }
  preg = pcre_compile("^\\{[a-zA-Z]{3} [a-zA-Z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}",
		      0, &errptr, &erroffset, NULL);
  if(pcre_exec(preg, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0) {
    return 3;
  }
  preg = pcre_compile("\\[[0-9]{2}/[a-zA-Z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}",
		      0, &errptr, &erroffset, NULL);
  if(pcre_exec(preg, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0) {
    return 4;
  }
  return 0;
}

/**
 * Creates the regular expression to match log lines for the curent hours
 * and all previous hours defined by the "hours" parameter.
 *
 * @param pool
 * @param hours How many hours (in past) to match
 * @param type Defines which time format is used within the log file.
 *             1 - ^2010-04-14 20:18:37
 *             2 - ^2010 12 04 20:46:45
 *             3 - ^[Mon Dec 06 21:29:07 2010]
 *             4 - [03/Dec/2010:07:36:51
 * @retrun pattern
 */
static pcre *qs_calc_regex(apr_pool_t *pool, int hours, int type) {
  const char *errptr = NULL;
  int erroffset;
  pcre *preg;
  char *pattern = "";
  int h = 1;
  char *(*f)(apr_pool_t *, int) = NULL;
  if(type == 1) {
    f = &qs_time_t12;
  } else if(type == 2) {
    f = &qs_time_t12;
  } else if(type == 3) {
    f = &qs_time_t3;
  } else if(type == 4) {
    f = &qs_time_t4;
  } else {
    fprintf(stderr, "ERROR - invalid type\n");
    exit(1);
  }
  pattern = f(pool, 0);
  
  for(h = 1; h <= hours; h++) {
    pattern = apr_pstrcat(pool, pattern, "|", f(pool, h), NULL);
  }

  if(type == 1 || type == 2) {
    pattern = apr_pstrcat(pool, "^", pattern, NULL);
  }
  if(type == 3) {
    pattern = apr_pstrcat(pool, "^\\[", pattern, NULL);
  }
  if(type == 4) {
    pattern = apr_pstrcat(pool, "\\[", pattern, NULL);
  }

  preg = pcre_compile(pattern, 0, &errptr, &erroffset, NULL);
  if(preg == NULL) {
    printf("faild to compile pattern %s: %s\n", pattern, errptr);
    exit(1);
  }

  return preg;
}

int main(int argc, const char *const argv[]) {
  int start = 0;
  char line[32768];
  int hours = 0;
  int type = 0;
  const char *pattern = NULL;
  apr_pool_t *pool;
  char *cmd = strrchr(argv[0], '/');
  const char *errptr = NULL;
  int erroffset;
  pcre *preg_tme;
  pcre *preg;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-h") == 0) {
      if (--argc >= 1) {
	hours = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-t") == 0) {
      if (--argc >= 1) {
	type = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-p") == 0) {
      if (--argc >= 1) {
	pattern = *(++argv);
      }
    } else if(strcmp(*argv,"-b") == 0) {
      if (--argc >= 1) {
	int len;
	const char *b = *(++argv);
	char *dec= apr_pcalloc(pool, apr_base64_decode_len(b));
	len = apr_base64_decode(dec, b);
	dec[len] = '\0';
	pattern = dec;
      }
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    }
    argc--;
    argv++;
  }

  if(pattern == NULL) {
    usage(cmd, 0);
  }
  preg = pcre_compile(pattern, 0, &errptr, &erroffset, NULL);
  if(preg == NULL) {
    printf("faild to compile pattern %s: %s\n", pattern, errptr);
    exit(1);
  }

  // start reading from stdin...
  if(fgets(line, sizeof(line), stdin) != NULL) {
    if(type == 0) {
      // auto detection of the time format
      type = qs_get_type(pool, line);
    }
    // compile the time matching pattern
    preg_tme = qs_calc_regex(pool, hours, type);

    // process the first line
    if(pcre_exec(preg_tme, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0) {
      if(pcre_exec(preg, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0) {
	printf("%s", line);
      }
    }
    // continue reading
    while(fgets(line, sizeof(line), stdin) != NULL) {
      if(!start && 
	 (pcre_exec(preg_tme, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0)) {
	start = 1; // found matching time string (all following lines are newer)
      }
      if(start) {
	if(pcre_exec(preg, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0) {
	  printf("%s", line);
	}
      }
    }
  }
  
  apr_pool_destroy(pool);
  return 0;
}
