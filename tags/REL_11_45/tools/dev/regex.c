/**
 * regex.c: pcre expression test tool
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2017 Pascal Buchbinder
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

/* OpenSSL  */
#include <openssl/stack.h>

/* apr */
#include <pcre.h>
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

#define MAX_LINE 32768
#define CR 13
#define LF 10
#define QS_OVECCOUNT 100


static void usage() {
  printf("usage: regex <string>|<path> <pcre>|<path>\n");
  printf("\n");
  printf("Regular expression matching test tool (pcre pattern, case less).\n");
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  exit(1);
}

static int rmatch(const char *line, pcre *pcre) {
  int ovector[QS_OVECCOUNT];
  int rc_c = -1;
  do {
    int rc = pcre_exec(pcre, NULL, line, strlen(line), 0, 0, ovector, QS_OVECCOUNT);
    if(rc >= 0) {
      rc_c = 0;
      printf("[%.*s]\n", ovector[1] - ovector[0], &line[ovector[0]]);
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
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  argc--;
  argv++;
  if(argc != 2) {
    usage();
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
  printf("pattern: %s\n", pattern);

  //pcre = pcre_compile(pattern, PCRE_CASELESS, &errptr, &erroffset, NULL);
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
      printf("line %.3d:\n", linenr);
      raw = apr_pstrcat(pool, raw, readline, NULL);
      while(len > 0 && readline[len] < 32) {
	readline[len] = '\0';
	len--;
      }
      if(readline[0] >= 32 && strlen(readline) > 0) {
	line = readline;
	rc_c = rmatch(line, pcre);
      }
    }
    fclose(file);
    printf("all:\n");
    rc_c = rmatch(raw, pcre);
  } else {
    line = in;
    rc_c = rmatch(line, pcre);
  }
  if(rc_c < 0) {
    printf("no match\n");
    return 2;
  }
  return 0;
}
