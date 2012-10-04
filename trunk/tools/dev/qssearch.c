/**
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2012 Pascal Buchbinder
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

static const char revision[] = "$Id: qssearch.c,v 1.1 2012-10-04 18:44:24 pbuchbinder Exp $";

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

  if(man) {
    exit(0);
  } else {
    exit(1);
  }
}

#define TMSRTLEN 128
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

static char *qs_time_t1(apr_pool_t *pool, int offset) {
  time_t tm = time(NULL);
  struct tm *ptr;
  char *time_string = apr_pcalloc(pool, TMSRTLEN);
  tm -= (offset * 3600);
  ptr = localtime(&tm);
  strftime(time_string, TMSRTLEN,
	   "(%Y[ -]%m[ -]%d %H:)", ptr);
  return time_string;
}

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
 *
 * type:
 * 1 - ^2010-04-14 20:18:37
 * 2 - ^2010 12 04 20:46:45
 * 3 - ^[Mon Dec 06 21:29:07 2010]
 * 4 - [03/Dec/2010:07:36:51
 */
static pcre *qs_calc_regex(apr_pool_t *pool, int hours, int type) {
  pcre *preg;
  char *pattern = "";
  int h = 1;
  char *(*f)(apr_pool_t *, int) = NULL;
  if(type == 1) {
    f = &qs_time_t1;
  } else if(type == 2) {
    f = &qs_time_t1;
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

  return preg;
}

int main(int argc, const char *const argv[]) {
  int hours = 0;
  int type = 0;
  const char *pattern = NULL;
  apr_pool_t *pool;
  char *cmd = strrchr(argv[0], '/');
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
    if(strcmp(*argv,"-d") == 0) {
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
  
  preg = qs_calc_regex(pool, hours, type);
  
  apr_pool_destroy(pool);
  return 0;
}
