/**
 * Utility for the quality of service module mod_qos.
 *
 * qsdt.c: simple tool to measure the elapse time between 
 *         related log messages
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2021 Pascal Buchbinder
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
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <regex.h>

#include <apr.h>
#include <apr_portable.h>
#include <apr_strings.h>

#include "qs_util.h"

#define MAX_REG_MATCH 10

#define TIMESTR "%H:%M:%S"
#define TIMEEX "([0-9]{2}:[0-9]{2}:[0-9]{2})[.,]([0-9]{3})"

typedef struct {
  time_t seconds;
  int milliseconds;
  char *id;
} entry_t;


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
  qs_man_print(man, "%s calculates the elapsed time between two related log messages.\n", cmd);
  printf("\n");

  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s [-t <regex>] -i <regex> -s <regex> -e <regex> [-v] [<path>]\n", man ? "" : "Usage: ", cmd);
  printf("\n");

  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "%s is a simple tool to search two different messages\n", cmd);
  qs_man_print(man, "in a log file and calculates the elapsed time between these\n");
  qs_man_print(man, "lines. The two log messages need a common identifier such an\n");
  qs_man_print(man, "unique request id (UNIQUE_ID), a thread id, or a transaction\n");
  qs_man_print(man, "code.\n");
  printf("\n");

  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -t <regex>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines a pattern (regular expression) matching the log line's\n");
  qs_man_print(man, "     timestamp. The pattern must include two sub-expressions, one matching\n");
  qs_man_print(man, "     hours, minutes and seconds the other matching the milliseconds.\n");
  qs_man_print(man, "     Default pattern is "TIMEEX"\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -i <regex>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Pattern (regular expression) matching the identifier which the two\n");
  qs_man_print(man, "     messages have in common. The sub-expression defines the part which\n");
  qs_man_print(man, "     needs to be extracted from the matching string. Note: You can also\n");
  qs_man_print(man, "     use the start (-s) and end (-e) pattern to define the sub-expression\n");
  qs_man_print(man, "     matching this identifier.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -s <regex>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the pattern (regular expression or literal string)\n");
  qs_man_print(man, "     identifying the first (start) of the two messages.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -e <regex>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the pattern (regular expression or literal string)\n");
  qs_man_print(man, "     identifying the second (end) of the two messages.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, " -v\n");
  if(man) printf("\n");
  qs_man_print(man, "     Verbose mode.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  <path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the input file to process. %s reads from\n", cmd);
  qs_man_print(man, "     from standard input if this parameter is omitted.\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
    printf("Sample command line arguments:\n");
    printf("\n");
  } else {
    printf(" Sample arguments:\n");
  }
  qs_man_println(man, "  -i ' ([a-z0-9]+) [A-Z]+ ' -s 'Received Request' -e 'Received Response'\n");
  printf("\n");
  qs_man_println(man, " matching those sample log messages:\n");
  qs_man_println(man, "  2018-03-12 16:34:08.653 threadid23 INFO Received Request\n");
  qs_man_println(man, "  2018-03-13 16:35:09.891 threadid23 DEBUG MessageHandler Received Response\n");
  printf("\n");
  if(man) {
    printf(".SH NOTE\n");
  } else {
    printf("Notes:\n");
  }
  qs_man_println(man, "The four patterns (t,i,s,e) are concatenated into two search patterns:\n");
  qs_man_println(man, " first (start): [t (HH:MM:SS)(SSS) ].*[i (id) ].*[s ]\n");
  qs_man_println(man, " second (end):  [t (HH:MM:SS)(SSS) ].*[i (id) ].*[e ]\n");
  printf("\n");
  qs_man_print(man, "And the three sub-expression are used to extract the timestamp and the\n");
  qs_man_print(man, "unique identifier that the start and end message have in common.\n");
  qs_man_print(man, "This means that you could specify the sub-expression for the unique\n");
  qs_man_print(man, "identifier in the start (-s) or end (-e) pattern alternatively, e.g. in\n");
  qs_man_print(man, "case the identifier is at the end of the log line.\n");
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qshead(1), qslog(1), qslogger(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qssign(1), qstail(1)\n");
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


int main(int argc, const char *const argv[]) {
  FILE *file;
  char line[MAX_LINE];
  int verbose = 0;
  
  const char *cmd = strrchr(argv[0], '/');

  apr_pool_t *pool;
  apr_table_t *inmsg;
 
  regmatch_t ma[MAX_REG_MATCH];
  regex_t pregstart;
  regex_t pregend;

  const char *timeex = TIMEEX;
  const char *idex = NULL;
  const char *startex = NULL;
  const char *endex = NULL;
  const char *filename = NULL;
  
  char *regexStr;
  
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  inmsg = apr_table_make(pool, 100);

  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-t") == 0) {
      if (--argc >= 1) {
        timeex = *(++argv);
      }
    } else if(strcmp(*argv,"-i") == 0) {
      if (--argc >= 1) {
        idex = *(++argv);
      }
    } else if(strcmp(*argv,"-s") == 0) {
      if (--argc >= 1) {
        startex = *(++argv);
      }
    } else if(strcmp(*argv,"-e") == 0) {
      if (--argc >= 1) {
        endex = *(++argv);
      }
    } else if(strcmp(*argv,"-v") == 0) {
      verbose = 1;
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    } else {
      filename = *argv;
    }
    argc--;
    argv++;
  }

  if(idex == NULL || startex == NULL || endex == NULL) {
    usage(cmd, 0);
  }

  if(filename) {
    file = fopen(filename, "r");
    if(!file) {
      fprintf(stderr, "ERROR, failed to open the log file '%s'\n", filename);
      exit(1);
    }
  } else {
    file = stdin;
  }


  regexStr = apr_psprintf(pool, "%s.*%s.*%s", timeex, idex, startex);
  if(verbose) {
    fprintf(stderr, "start pattern: %s\n", regexStr);
  }
  if(regcomp(&pregstart, regexStr, REG_EXTENDED)) {
    fprintf(stderr, "ERROR, could not compile %s\n", regexStr);
    exit(1);
  };
  regexStr = apr_psprintf(pool, "%s.*%s.*%s", timeex, idex, endex);
  if(verbose) {
    fprintf(stderr, "end pattern: %s\n", regexStr);
  }
  if(regcomp(&pregend, regexStr, REG_EXTENDED)) {
    fprintf(stderr, "ERROR, could not compile %s\n", regexStr);
    exit(1);
  };

  while(fgets(line, MAX_LINE-1, file) != NULL) {
    char *hms;
    char *ms;
    char *id;
    if(regexec(&pregstart, line, MAX_REG_MATCH, ma, 0) == 0) {
      entry_t *entry = calloc(1, sizeof(entry_t));
      struct tm tm;
      if(ma[3].rm_so == -1) {
	fprintf(stderr, "ERROR, invalid regular expression (missing sub-expression in pattern)\n");
	exit(1);
      }
      hms = &line[ma[1].rm_so];
      ms = &line[ma[2].rm_so];
      id = &line[ma[3].rm_so];
      line[ma[1].rm_eo] = '\0';
      line[ma[2].rm_eo] = '\0';
      line[ma[3].rm_eo] = '\0';
      strptime(hms, TIMESTR, &tm);
      entry->seconds = mktime(&tm);
      entry->milliseconds = atoi(ms);
      entry->id = calloc(strlen(id)+1, sizeof(char));
      sprintf(entry->id, "%s", id);
      if(verbose) {
	fprintf(stderr, "START [%s][%s][%s] %lu %d\n",
		hms, ms, id, entry->seconds, entry->milliseconds);
      }
      apr_table_setn(inmsg, entry->id, (char *)entry);
    } else if(regexec(&pregend, line, MAX_REG_MATCH, ma, 0) == 0) {
      entry_t entry;
      entry_t *start;
      struct tm tm;
      if(ma[3].rm_so == -1) {
	fprintf(stderr, "ERROR, invalid regular expression (missing sub-expression in pattern)\n");
	exit(1);
      }
      hms = &line[ma[1].rm_so];
      ms = &line[ma[2].rm_so];
      id = &line[ma[3].rm_so];
      line[ma[1].rm_eo] = '\0';
      line[ma[2].rm_eo] = '\0';
      line[ma[3].rm_eo] = '\0';
      strptime(hms, TIMESTR, &tm);
      entry.seconds = mktime(&tm);
      entry.milliseconds = atoi(ms);
      if(verbose) {
	fprintf(stderr, "END [%s][%s][%s] %lu %d\n",
		hms, ms, id, entry.seconds, entry.milliseconds);
      }
      start = (entry_t *)apr_table_get(inmsg, id);
      if(start) {
	printf("@%s %s %10lu [ms]\n",
	       line,
	       id,
	       (entry.seconds-start->seconds)*1000 + entry.milliseconds-start->milliseconds);
	apr_table_unset(inmsg, id);
	free(start->id);
	free(start);
      }
    }
  }
  fclose(file);

  return 0;
}
