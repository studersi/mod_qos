/**
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2007-2009 Pascal Buchbinder
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

static const char revision[] = "$Id: crs.c,v 1.1 2009-11-16 07:42:33 pbuchbinder Exp $";

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
