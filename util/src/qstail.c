/**
 * Utilities for the quality of service module mod_qos.
 *
 * Shows the end of a log file beginning at the provided pattern.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2010-2011 Pascal Buchbinder
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

static const char revision[] = "$Id: qstail.c,v 1.7 2011-01-01 20:52:04 pbuchbinder Exp $";

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <signal.h>

#define MAX_LINE 32768
#define CR 13
#define LF 10
#define BUFFER 2048

static void usage(char *cmd) {
  printf("\n");
  printf("Utility prints the end of a log file starting at the specified pattern.\n");
  printf("\n");
  printf("Usage: %s -i <path> -p <pattern>\n", cmd);
  printf("\n");
  printf("Summary\n");
  printf(" %s shows the end of a log file beginning with the line containing the\n", cmd);
  printf(" specified pattern. This may be used to show all lines which has been written\n");
  printf(" after a certain event (e.g., server restart) or time stamp.\n");
  printf("\n");
  printf("Options\n");
  printf("  -i <path>\n");
  printf("     Input file to read the data from.\n");
  printf("  -p <pattern>\n");
  printf("     Search pattern (literal string).\n");
  printf("\n");
  printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
  exit(1);
}

/* search the beginning of the line starting at the provided position */
static void qs_readline(long pos, FILE *f) {
  size_t len;
  long startpos = pos - BUFFER + 1;
  long readlen = BUFFER;
  char line[readlen + 1];
  if(startpos < 0) {
    // we are at the beginning of the file
    startpos = 0;
    readlen = pos + 1;
  }
  fseek(f, startpos, SEEK_SET);
  len = fread(&line, 1, readlen, f);
  if(len > 0) {
    char *s = &line[len-1];
    line[len] = '\0';
    while((s >= line) && (s[0] != CR) && (s[0] != LF)) {
      s--;
    }
    if((s[0] == CR) || (s[0] != LF)) {
      s++;
    }
    printf("%s", s);
  }
}

static int qs_tail(const char *cmd, FILE *f, const char *pattern) {
  long search_win_len = strlen(pattern) * 2 + 32;
  char line[search_win_len + 10];
  long pos = 0;
  size_t len;
  char *startpattern = NULL;
  fseek(f, 0L, SEEK_END);
  pos = ftell(f);
  while(pos > search_win_len) {
    int offset = 0;
    pos = pos - (search_win_len/2);
    fseek(f, pos, SEEK_SET);
    len = fread(&line, 1, search_win_len, f);
    if(len <= 0) {
      /* pattern not found / reached end */
      return 1;
    }
    line[len] = '\0';
    if((startpattern = strstr(line, pattern)) != NULL) {
      int containsend = 0;
      char *s = startpattern;
      char *end;
      offset = startpattern - line;
      /* search the beginning of the line */
      while((s > line) && (s[0] != CR) && (s[0] != LF)) {
	s--;
      }
      if((s[0] != CR) && (s[0] != LF)) {
	// beginning of the line not in the buffer
	qs_readline(pos, f);
      }
      s++;
      end = startpattern;
      /* search the end of the line */
      while(end && end[0] && end[0] != CR && end[0] != LF) {
	end++;
	offset++;
      }
      /* print the line containing the pattern */
      if((end[0] == CR) || (end[0] == LF)) {
	end[0] = '\0';
	printf("%s\n", s);
	containsend = 1;
      } else {
	printf("%s", s);
      }
      fseek(f, pos + offset, SEEK_SET);
      if(containsend) {
	// skip the line at the  current position
	fgets(line, sizeof(line), f);
      }
      while(fgets(line, sizeof(line), f) != NULL) {
	printf("%s", line);
      }
      return 0;
    }
  }
  return 1;
}

int main(int argc, const char * const argv[]) {
  FILE *f;
  const char *filename = NULL;
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
    if(strcmp(*argv,"-i") == 0) {
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
  
  status = qs_tail(cmd, f, pattern);

  fclose(f);
  return status;
}
