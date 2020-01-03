/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */
/**
 * Command line execution utility for the quality of service module mod_qos.
 *
 * See http://mod-qos.sourceforge.net/ for further details.
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

/* apr */
#include <pcre.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>

#include "qs_util.h"

#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif
#define MAX_REG_MATCH 10

/* same as APR_SIZE_MAX which doesn't appear until APR 1.3 */
#define QSUTIL_SIZE_MAX (~((apr_size_t)0))

typedef struct {
    int rm_so;
    int rm_eo;
} regmatch_t;

static void usage(char *cmd, int man) {
  if(man) {
    //.TH [name of program] [section number] [center footer] [left footer] [center header]
    printf(".TH %s 1 \"%s\" \"mod_qos utilities %s\" \"%s man page\n", qs_CMD(cmd), man_date, man_version, cmd);
  }
  printf("\n");
  if(man) {
    printf(".SH NAME\n");
  }
  printf("%s %s- parses the data received via stdin and executes the defined command on a pattern match.\n",
         cmd, man ? "\\" : "");
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -e <pattern> [-t <number>:<sec>] [-c <pattern> [<command string>]]\n", man ? "" : "Usage: ", cmd);
  qs_man_print(man, "       [-p] [-u <user>] <command string>\n");
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "%s reads log lines from stdin and searches for the defined pattern.\n", cmd);
  qs_man_print(man, "It executes the defined command string on pattern match.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -e <pattern>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifes the search pattern causing an event which shall trigger the\n");
  qs_man_print(man, "     command.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -t <number>:<sec>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the number of pattern match within the the defined number of\n");
  qs_man_print(man, "     seconds in order to trigger the command execution. By default, every\n");
  qs_man_print(man, "     pattern match causes a command execution.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -c <pattern> [<command string>]\n");
  if(man) printf("\n");
  qs_man_print(man, "     Pattern which clears the event counter. Executes optionally a command\n");
  qs_man_print(man, "     if an event command has been executed before.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -p\n");
  if(man) printf("\n");
  qs_man_print(man, "     Writes data also to stdout (for piped logging).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -u <name>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Become another user, e.g. www-data.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  <command string>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the event command string where $0-$9 are substituted by the\n");
  qs_man_print(man, "     submatches of the regular expression.\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
  } else {
    printf("Example:\n");
  }
  qs_man_print(man, "Executes the deny.sh script providing the IP address of the\n");
  qs_man_print(man, "client causing a mod_qos(031) messages whenever the log message\n");
  qs_man_print(man, "appears 10 times within at most one minute:\n");
  if(man) printf("\n");
  qs_man_println(man, "  ErrorLog \"|/usr/bin/%s -e \\'mod_qos\\(031\\).*, c=([0-9a-zA-Z:.]*)\\' -t 10:60 \\'/usr/local/bin/deny.sh $1\\'\"\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsfilter2(1), qsgeo(1), qsgrep(1), qshead(1), qslog(1), qslogger(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qssign(1), qstail(1)\n");
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

/*
 * Substitutes for $0-$9 within the matching string.
 * See ap_pregsub().
 */
char *qs_pregsub(apr_pool_t *pool, const char *input,
		 const char *source, size_t nmatch,
		 regmatch_t pmatch[]) {
  const char *src = input;
  char *dest, *dst;
  char c;
  size_t no;
  int len;
  if(!source) {
    return NULL;
  }
  if(!nmatch) {
    return apr_pstrdup(pool, src);
  }
  /* First pass, find the size */  
  len = 0;
  while((c = *src++) != '\0') {
    if(c == '&')
      no = 0;
    else if (c == '$' && apr_isdigit(*src))
      no = *src++ - '0';
    else
      no = 10;
    
    if (no > 9) {                /* Ordinary character. */
      if (c == '\\' && (*src == '$' || *src == '&'))
	src++;
      len++;
    }
    else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
      if(QSUTIL_SIZE_MAX - len <= pmatch[no].rm_eo - pmatch[no].rm_so) {
        fprintf(stderr, "ERROR, integer overflow or out of memory condition");
        return NULL;
      }
      len += pmatch[no].rm_eo - pmatch[no].rm_so;
    }
    
  }
  dest = dst = apr_pcalloc(pool, len + 1);
  /* Now actually fill in the string */
  src = input;
  while ((c = *src++) != '\0') {
    if (c == '&')
      no = 0;
    else if (c == '$' && apr_isdigit(*src))
      no = *src++ - '0';
    else
      no = 10;

    if (no > 9) {                /* Ordinary character. */
      if (c == '\\' && (*src == '$' || *src == '&'))
        c = *src++;
      *dst++ = c;
    }
    else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
      len = pmatch[no].rm_eo - pmatch[no].rm_so;
      memcpy(dst, source + pmatch[no].rm_so, len);
      dst += len;
    }
  }
  *dst = '\0';
  return dest;
}

int qs_regexec(pcre *preg, const char *string,
	       apr_size_t nmatch, regmatch_t pmatch[]) {
  int rc;
  int options = 0;
  int *ovector = NULL;
  int small_ovector[POSIX_MALLOC_THRESHOLD * 3];
  int allocated_ovector = 0;
  if (nmatch > 0) {
    if (nmatch <= POSIX_MALLOC_THRESHOLD) {
      ovector = &(small_ovector[0]);
    } else {
      ovector = (int *)malloc(sizeof(int) * nmatch * 3);
      if (ovector == NULL) {
	return 1;
      }
      allocated_ovector = 1;
    }
  }
  rc = pcre_exec(preg, NULL, string, (int)strlen(string), 0, options, ovector, nmatch * 3);
  if (rc == 0) rc = nmatch;    /* All captured slots were filled in */
  if (rc >= 0) {
    apr_size_t i;
    for (i = 0; i < (apr_size_t)rc; i++) {
      pmatch[i].rm_so = ovector[i*2];
      pmatch[i].rm_eo = ovector[i*2+1];
    }
    if (allocated_ovector) free(ovector);
    for (; i < nmatch; i++) pmatch[i].rm_so = pmatch[i].rm_eo = -1;
    return 0;
  } else {
    if (allocated_ovector) free(ovector);
    return rc;
  }
}

int main(int argc, const char * const argv[]) {
  const char *username = NULL;
  int nr = 0;
  char *line = calloc(1, MAX_LINE_BUFFER+1);
  apr_pool_t *pool;
  char *cmd = strrchr(argv[0], '/');
  const char *command = NULL;
  const char *pattern = NULL;
  const char *clearcommand = NULL;
  const char *clearpattern = NULL;
  int executed = 0;
  pcre *preg;
  pcre *clearpreg;
  const char *errptr = NULL;
  int erroffset;
  regmatch_t regm[MAX_REG_MATCH];
  time_t sec = 0;
  int threshold = 0;
  int counter = 0;
  time_t countertime;
  static int pass = 0;
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
    if(strcmp(*argv,"-e") == 0) {
      if (--argc >= 1) {
	pattern = *(++argv);
      }
    } else if(strcmp(*argv,"-u") == 0) {
      if (--argc >= 1) {
	username = *(++argv);
      }
    } else if(strcmp(*argv,"-c") == 0) {
      if (--argc >= 1) {
	clearpattern = *(++argv);
	if (argc >=1 && *argv[0] != '-') {
	  clearcommand = *(++argv);
	  argc--;
	}
      }
    } else if(argc >= 1 && strcmp(*argv,"-t") == 0) {
      if (--argc >= 1) {
	char *str = apr_pstrdup(pool, *(++argv));
	char *tme = strchr(str, ':');
	if(tme == NULL) {
	  fprintf(stderr,"[%s]: ERROR, invalid number:sec format\n", cmd);
	  exit(1);
	}
	tme[0] = '\0';
	tme++;
	threshold = atoi(str);
	sec = atol(tme);
	if(threshold == 0 || sec == 0) {
	  fprintf(stderr,"[%s]: ERROR, invalid number:sec format\n", cmd);
	  exit(1);
	}
      }
    } else if(argc >= 1 && strcmp(*argv,"-p") == 0) {
      pass = 1;
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    } else {
      command = *argv;
    }
    argc--;
    argv++;
  }

  if(pattern == NULL || command == NULL) {
    usage(cmd, 0);
  }

  qs_setuid(username, cmd);

  preg = pcre_compile(pattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(!preg) {
    fprintf(stderr, "ERROR, could not compile '%s' at position %d, reason: %s\n",
	    pattern, erroffset, errptr);
    exit(1);
  }
  if(clearpattern) {
    clearpreg = pcre_compile(clearpattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
    if(!clearpreg) {
      fprintf(stderr, "ERROR, could not compile '%s' at position %d, reason: %s\n",
	      clearpattern, erroffset, errptr);
      exit(1);
    }
  }

  while(fgets(line, MAX_LINE_BUFFER, stdin) != NULL) {
    nr++;
    if(pass) {
      printf("%s", line);
      fflush(stdout);
    }
    if(clearpattern && (qs_regexec(clearpreg, line, MAX_REG_MATCH, regm) == 0)) {
      counter = 0;
      countertime = 0;
      if(clearcommand && executed) {
	char *replaced = qs_pregsub(pool, clearcommand, line, MAX_REG_MATCH, regm);
	if(!replaced) {
	  fprintf(stderr, "[%s]: ERROR, failed to substitute"
                  " submatches '%s' in (%s)\n", cmd, clearcommand, line);
	} else {
	  int rc = system(replaced);
	}
	executed = 0;
      }
    } else if(qs_regexec(preg, line, MAX_REG_MATCH, regm) == 0) {
      char *replaced = qs_pregsub(pool, command, line, MAX_REG_MATCH, regm);
      if(!replaced) {
	fprintf(stderr, "[%s]: ERROR, failed to substitute"
                " submatches '%s' in (%s)\n", cmd, command, line);
      } else {
	counter++;
	if(counter == 1) {
	  countertime = time(NULL);
	}
	if(counter >= threshold) {
	  if(countertime + sec >= time(NULL)) {
	    int rc = system(replaced);
	    executed = 1;
	  }
	  countertime = 0;
	  counter = 0;
	}
      }
      apr_pool_clear(pool);
    }
  }
  
  apr_pool_destroy(pool);
  return 0;
}
