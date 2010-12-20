/**
 * Utilities for the quality of service module mod_qos.
 *
 * Shows the end of a log file beginning at the provided pattern.
 *
 * See http://opensource.adnovum.ch/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2010 Pascal Buchbinder
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

static const char revision[] = "$Id: qstail.c,v 1.1 2010-12-20 20:02:01 pbuchbinder Exp $";

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <signal.h>

#define MAX_LINE 32768
#define CR 13
#define LF 10

static void usage(char *cmd) {
  printf("\n");
  printf("Utility prints the end of a log file starting at the specified pattern.\n");
  printf("\n");

  exit(1);
}

static void qs_tail(const char *cmd, FILE *f, const char *pattern) {
  long search_win_len = strlen(pattern) * 2 + 512;
  long line_len = MAX_LINE;
  char line[MAX_LINE];
  long pos = 0;
  size_t len;
  char *start;
  fseek(f, 0L, SEEK_END);
  pos = ftell(f);
  while(pos > search_win_len) {
    int offset = 0;
    pos = pos - (search_win_len/2);
    fseek(f, pos, SEEK_SET);
    len = fread(&line, 1, search_win_len, f);
    if(len <= 0) {
      /* pattern not found / reached end */
      return;
    }
    line[len] = '\0';
    if((start = strstr(line, pattern)) != NULL) {
      char *s = start;
      offset = start - line;
      while((s > line) && (s[0] != CR) && (s[0] != LF)) {
	s--;
      }
      s++;
      while(start && start[0] && start[0] != CR && start[0] != LF) {
	start++;
	offset++;
      }
      start[0] = '\0';
      printf("%s\n", s);
      fseek(f, pos + offset, SEEK_SET);
      if(fgets(line, sizeof(line), f) != NULL) {
	while(fgets(line, sizeof(line), f) != NULL) {
	  printf("%s", line);
	}
      }
      return;
    }
  }
  return;
}

int main(int argc, const char * const argv[]) {
  FILE *f;
  const char *filename = NULL;
  const char *pattern = NULL;
  char *cmd = strrchr(argv[0], '/');
  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-f") == 0) {
      if (--argc >= 1) {
	filename = *(++argv);
      }
    } else if(strcmp(*argv,"-p") == 0) {
      if (--argc >= 1) {
	pattern = *(++argv);
      } 
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd);
    }
    argc--;
    argv++;
  }

  if(filename == NULL || pattern == NULL) {
    usage(cmd);
  }
  if((f = fopen(filename, "r")) == NULL) {
    fprintf(stderr, "[%s]: ERROR, could not open file '%s'\n", cmd, filename);
    exit(1);
  }
  
  qs_tail(cmd, f, pattern);

  fclose(f);
  return 0;
}
