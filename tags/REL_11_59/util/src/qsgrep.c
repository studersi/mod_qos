/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */
/**
 * Filter utility for the quality of service module mod_qos.
 *
 * qsgrep.c: simple tool to search patterns within files
 *
 * See http://mod-qos.sourceforge.net/ for further details.
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

/* system */
#include <stdio.h>
#include <errno.h>
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
    printf(".TH %s 1 \"%s\" \"mod_qos utilities %s\" \"%s man page\"\n", qs_CMD(cmd), man_date,
	   man_version, cmd);
  }
  printf("\n");
  if(man) {
    printf(".SH NAME\n");
  }
  qs_man_print(man, "%s - prints matching patterns within a file.\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -e <pattern> -o <sub string> [<path>]\n", man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "%s is a simple tool to search patterns within files.\n", cmd);
  qs_man_print(man, "It uses regular expressions to find patterns and prints the\n");
  qs_man_print(man, "submatches within a pre-defined format string.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -e <pattern>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifes the search pattern.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -o <string>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the output string where $0-$9 are substituted by the\n");
  qs_man_print(man, "     submatches of the regular expression.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  <path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the input file to process. %s reads from\n", cmd);
  qs_man_print(man, "     from standard input if this parameter is omitted.\n");
  printf("\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
    qs_man_println(man, "Shows the IP addresses of clients causing mod_qos(031) messages):\n");
    printf("\n");
  } else {
    printf("Example (shows the IP addresses of clients causing mod_qos(031) messages):\n");
  }
  qs_man_println(man, "  %s -e 'mod_qos\\(031\\).*, c=([a-zA-Z0-9:.]*)' -o 'ip=$1' error_log\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsfilter2(1), qsgeo(1), qshead(1), qslog(1), qslogger(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qssign(1), qstail(1)\n");
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
  unsigned long nr = 0;
  char line[32768];
  FILE *file = 0;
  apr_pool_t *pool;
  char *cmd = strrchr(argv[0], '/');
  const char *out = NULL;
  const char *pattern = NULL;
  const char *filename = NULL;
  pcre *preg;
  const char *errptr = NULL;
  int erroffset;
  regmatch_t regm[MAX_REG_MATCH];
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
    } else if(strcmp(*argv,"-o") == 0) {
      if (--argc >= 1) {
	out = *(++argv);
      }
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    } else {
      filename = *argv;
    }
    argc--;
    argv++;
  }

  if(pattern == NULL || out == NULL) {
    usage(cmd, 0);
  }

  if(nice(10) == -1) {
    fprintf(stderr, "ERROR, failed to change nice value: %s\n", strerror(errno));
  }

  preg = pcre_compile(pattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(!preg) {
    fprintf(stderr, "ERROR, could not compile '%s' at position %d, reason: %s\n",
	    pattern, erroffset, errptr);
    exit(1);
  }

  if(filename) {
    file = fopen(filename, "r");
    if(!file) {
      fprintf(stderr, "ERROR, could not open file\n");
      exit(1);
    }
  } else {
    file = stdin;
  }
    
  while(fgets(line, sizeof(line), file) != NULL) {
    nr++;
    if(qs_regexec(preg, line, MAX_REG_MATCH, regm) == 0) {
      char *replaced = qs_pregsub(pool, out, line, MAX_REG_MATCH, regm);
      if(!replaced) {
	fprintf(stderr, "ERROR, failed to substitute submatches (line=%lu)\n", nr);
      } else {
	printf("%s\n", replaced);
        fflush(stdout);
      }
      apr_pool_clear(pool);
    }
  }

  if(filename) {
    fclose(file);
  }
  apr_pool_destroy(pool);
  return 0;
}
