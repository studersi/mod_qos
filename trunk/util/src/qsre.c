/**
 * qsre.c: pcre expression match test tool
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2019 Pascal Buchbinder
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
#include <apr_time.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>

#include "qs_util.h"

#define QS_OVECCOUNT 100


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
  qs_man_print(man, "%s matches a regular expression against test strings.\n", cmd);
  printf("\n");

  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s <string>|<path> <pcre>|<path>\n", man ? "" : "Usage: ", cmd);
  printf("\n");

  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "Regular expression test tool.\n");
  qs_man_print(man, "The provided regular expression (pcre, caseless matching, \".\" matches anything\n");
  qs_man_print(man, "incl. newline) is appplied against the provided test strings to verify if the\n");
  qs_man_print(man, "pattern matches.\n");
  printf("\n");

  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  <string>|<path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     The first argument either defines a sinlge test string of a path to\n");
  qs_man_print(man, "     a file containing either multiple test strings or a test pattern with\n");
  qs_man_print(man, "     newline characters (text).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  <pcre>|<path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     The second argument either defines a regular expression or a path to\n");
  qs_man_print(man, "     a file containing the expression.\n");
  printf("\n");

  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qshead(1), qslog(1), qslogger(1), qspng(1), qsrespeed(1), qsrotate(1), qssign(1), qstail(1)\n");
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

static int rmatch(const char *line, pcre *pcre) {
  int ovector[QS_OVECCOUNT];
  int rc_c = -1;
  do {
    int rc = pcre_exec(pcre, NULL, line, strlen(line), 0, 0, ovector, QS_OVECCOUNT);
    if(rc >= 0) {
      int ix;
      rc_c = 0;
      printf("[%.*s]", ovector[1] - ovector[0], &line[ovector[0]]);
      for(ix = 1; ix < rc; ix++) {
	printf(" $%d=%.*s", ix, ovector[ix*2+1] - ovector[ix*2], &line[ovector[ix*2]]);
      }
      line = &line[ovector[1]];
      if(ovector[1] - ovector[0] == 0) {
	line++;
      }
    } else {
      line = NULL;
    }
  } while(line && line[0]);
  return rc_c;
}

int main(int argc, const char *const argv[]) {
  const char *errptr = NULL;
  int erroffset;
  pcre *pcre;
  int rc_c = -1;
  const char *line;
  const char *in;
  const char *pattern;
  FILE *file;
  apr_pool_t *pool;
  char *raw = "";
  int linenr = 0;

  const char *cmd = strrchr(argv[0], '/');

  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  if(argc != 2) {
    if(argc  == 1 && strcmp(argv[0], "--man") == 0) {
      usage(cmd, 1);
    } else {
      usage(cmd, 0);
    }
  }
  in = argv[0];
  pattern = argv[1];

  file = fopen(pattern, "r");
  if(file) {
    char readline[MAX_LINE];
    if(fgets(readline, MAX_LINE-1, file) != NULL) {
      int len = strlen(readline);
      while(len > 0 && readline[len] < 32) {
	readline[len] = '\0';
	len--;
      }
      pattern = apr_pstrdup(pool, readline);
    }
    fclose(file);
  }
  printf("expression: %s\n", pattern);

  pcre = pcre_compile(pattern, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre == NULL) {
    fprintf(stderr, "ERROR, rule <%s> could not compile pcre at position %d,"
	    " reason: %s\n", pattern, erroffset, errptr);
    exit(1);
  }

  file = fopen(in, "r");
  if(file) {
    char readline[MAX_LINE];
    while(fgets(readline, MAX_LINE-1, file) != NULL) {
      int len = strlen(readline);
      linenr++;
      printf("line %.3d: ", linenr);
      raw = apr_pstrcat(pool, raw, readline, NULL);
      while(len > 0 && readline[len] < 32) {
	readline[len] = '\0';
	len--;
      }
      if(readline[0] >= 32 && strlen(readline) > 0) {
	line = readline;
	rc_c = rmatch(line, pcre);
      }
      printf("\n");
    }
    fclose(file);
    printf("entire content match:\n");
    rc_c = rmatch(raw, pcre);
    printf("\n");
  } else {
    line = in;
    rc_c = rmatch(line, pcre);
    printf("\n");
  }
  if(rc_c < 0) {
    printf("no match\n");
    return 2;
  }
  return 0;
}
