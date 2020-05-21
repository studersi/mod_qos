/**
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

static void usage() {
  printf("usage: crs -c <path>\n");
  printf("reformats the provided crs file showing secrule variables and operator only\n");
  exit(1);
}

static void crs_trim(char *line) {
  int i = 0;
  char *p;
  int c = 0;
  if(strlen(line) > 0) {
    /* cut end */
    p = &line[strlen(line)-1];
    while(p && p[0] && p[0] <= ' ') {
      p[0] = '\0';
      p--;
    }
  }
  /* cut spaces */
  p = line;
  while(p && p[0]) {
    if(!c && (p[0] <= ' ')) {
      p++;
    } else {
      c = 1;
      if(p[0] < ' ') {
	line[i] = ' ';
      } else {
	line[i] = p[0];
      }
      p++;
      i++;
    }
  }
  if(p != line) {
    line[i] = '\0';
  }
}

static char *crs_fgets(char *line, int len, FILE *file) {
  char *r = fgets(line, len, file);
  crs_trim(line);
  if((r != NULL) && (line[strlen(line)-1] == '\\')) {
    char next[32768];
    r = fgets(next, sizeof(next), file);
    strcpy(&line[strlen(line)-1], next);
    crs_trim(line);
  }
  return r;
}

int main(int argc, char **argv) {
  const char *filename = NULL;
  FILE *file;
  while(argc >= 1) {
    if(strcmp(*argv,"-c") == 0) {
      if (--argc >= 1) {
	filename = *(++argv);
      }
    }
    argc--;
    argv++;
  }
  if(!filename) {
    usage();
  }
  file = fopen(filename, "r");
  if(!file) {
    fprintf(stderr, "ERROR, could not open file\n");
  } else {
    char line[32768];
    while(crs_fgets(line, sizeof(line), file) != NULL) {
      if(strncmp(line, "SecRule ", strlen("SecRule ")) == 0) {
	char *type = &line[strlen("SecRule ")];
	char *pattern;
	//printf("rule={%s}\n", line);
	crs_trim(type);
	//printf("type=[%s]\n", type);
	pattern = strstr(type, " \"");
	if(pattern) {
	  char *end;
	  pattern[0] = '\0';
	  crs_trim(type);
	  pattern=pattern+2;
	  end = pattern;
	  while(end && end[0]) {
	    end = strstr(end, "\" ");
	    if(end[-1] != '\\') {
	      printf(".");
	      end[0] = '\0';
	    } else {
	      end++;
	    }
	  }
	  printf("%s \"%s\"\n", type, pattern);
	}
      }
    }
    fclose(file);
  }
  return 0;
}
