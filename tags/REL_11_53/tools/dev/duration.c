/**
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

#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <regex.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>

#define MAX_LINE 8192
#define MAX_REG_MATCH 10

#define TIMESTR "%H:%M:%S"
#define START "^[0-9_:.,-]+[_ -]([0-9:]+)[.,]([0-9]{3}) ([a-z0-9]+) [A-Z]+ Received HTTPRequest"
#define END   "^[0-9_:.,-]+[_ -]([0-9:]+)[.,]([0-9]{3}) ([a-z0-9]+) [A-Z]+ .*Received response"

typedef struct {
  time_t seconds;
  int milliseconds;
  char *id;
} entry_t;

int main(int argc, const char *const argv[]) {
  FILE *file;
  char line[MAX_LINE];

  apr_pool_t *pool;
  apr_table_t *inmsg;
 
  regmatch_t ma[MAX_REG_MATCH];
  regex_t pregstart;
  regex_t pregend;

  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  inmsg = apr_table_make(pool, 100);

  if(argc < 4) {
    printf("\n");
    printf("Usage: duration <path> <start pattern> <end pattern>\n");
    printf("\n");
    printf("Messsage start/end pattern must contain 3 sub-expressions:\n");
    printf(" - HH:MM:SS\n");
    printf(" - milliseconds\n");
    printf(" - id (transaction, thread, or similar id for correaltion)\n");
    printf("\n");
    printf(" Sample pattern:\n");
    printf("  "START"\n");
    printf("  "END"\n");
    printf("\n");
    exit(1);
  }

  if(regcomp(&pregstart, argv[2], REG_EXTENDED)) {
    fprintf(stderr, "ERROR, could not compile %s\n", argv[2]);
    exit(1);
  };
  if(regcomp(&pregend, argv[3], REG_EXTENDED)) {
    fprintf(stderr, "ERROR, could not compile %s\n", argv[3]);
    exit(1);
  };

  file = fopen(argv[1], "r");
  if(file) {
    while(fgets(line, MAX_LINE-1, file) != NULL) {
      if(regexec(&pregstart, line, MAX_REG_MATCH, ma, 0) == 0) {
	char *hms = &line[ma[1].rm_so];
	char *ms = &line[ma[2].rm_so];
	char *id = &line[ma[3].rm_so];
	entry_t *entry = calloc(1, sizeof(entry_t));
	struct tm tm;
	line[ma[1].rm_eo] = '\0';
	line[ma[2].rm_eo] = '\0';
	line[ma[3].rm_eo] = '\0';
	strptime(hms, TIMESTR, &tm);
	entry->seconds = mktime(&tm);
	entry->milliseconds = atoi(ms);
	entry->id = calloc(strlen(id)+1, sizeof(char));
	sprintf(entry->id, "%s", id);
	//printf("START [%s][%s][%s] %lu %d\n", hms, ms, id, entry->seconds, entry->milliseconds);
	apr_table_setn(inmsg, entry->id, (char *)entry);
      } else if(regexec(&pregend, line, MAX_REG_MATCH, ma, 0) == 0) {
	char *hms = &line[ma[1].rm_so];
	char *ms = &line[ma[2].rm_so];
	char *id = &line[ma[3].rm_so];
	entry_t entry;
	entry_t *start;
	struct tm tm;
	line[ma[1].rm_eo] = '\0';
	line[ma[2].rm_eo] = '\0';
	line[ma[3].rm_eo] = '\0';
	strptime(hms, TIMESTR, &tm);
	entry.seconds = mktime(&tm);
	entry.milliseconds = atoi(ms);
	//printf("END [%s][%s][%s] %lu %d\n", hms, ms, id, entry.seconds, entry.milliseconds);
	start = (entry_t *)apr_table_get(inmsg, id);
	if(start) {
	  printf("%10lu [ms] @%s %s\n",
		 (entry.seconds-start->seconds)*1000 + entry.milliseconds-start->milliseconds,
		 line,
		 id);
	  apr_table_unset(inmsg, id);
	  free(start->id);
	  free(start);
	}
      }
    }
    fclose(file);
  } else {
    fprintf(stderr, "ERROR, faild to open the log file '%s'\n", argv[1]);
    exit(1);
  }
  return 0;
}
