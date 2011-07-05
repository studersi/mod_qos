/**
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2010 Pascal Buchbinder
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

static const char revision[] = "$Id: regex.c,v 1.8 2011-07-05 17:51:32 pbuchbinder Exp $";

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
  printf("usage: regex <string>|<path> <pcre>\n");
  printf("\n");
  printf("Regular expression matching test tool (pcre pattern, case less).\n");
  printf("\n");
  printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
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

  argc--;
  argv++;
  if(argc != 2) {
    usage();
  }
  in = argv[0];
  pattern = argv[1];

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
