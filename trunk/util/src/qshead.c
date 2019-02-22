/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */
/**
 * Utilities for the quality of service module mod_qos.
 *
 * qshead.c: Shows the beginning of a log file stopping at the provided pattern.
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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <signal.h>

#include "qs_util.h"

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
  qs_man_print(man, "%s - an utility reading from stdin and printing all"
               " lines to stdout until"
               " reaching the defined pattern.\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -p <pattern>\n", man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, " %s reads lines from stdin and prints them to stdout unitl a line contains\n", cmd);
  qs_man_print(man, " the specified pattern (literal string).\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -p <pattern>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Search pattern (literal string).\n");
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qslog(1), qslogger(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qssign(1) qstail(1)\n");
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
  char line[32768];
  const char *pattern = NULL;
  char *cmd = strrchr(argv[0], '/');
  int status = 0;
  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-p") == 0) {
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

  if(pattern == NULL) {
    usage(cmd, 0);
  }

  while(fgets(line, sizeof(line), stdin) != NULL) {
    printf("%s", line);
    if(strstr(line, pattern)) {
      return status;
    }
  }
  return status;
}
