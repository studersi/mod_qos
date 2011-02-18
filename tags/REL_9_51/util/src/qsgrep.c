/**
 * Filter utility for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further details.
 *
 * Copyright (C) 2011 Pascal Buchbinder
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is released under the GPL with the additional
 * exemption that compiling, linking, and/or using OpenSSL is allowed.
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

static const char revision[] = "$Id: qsgrep.c,v 1.1 2011-02-10 19:28:56 pbuchbinder Exp $";

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
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>

#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif
#define MAX_REG_MATCH 10

typedef struct {
    int rm_so;
    int rm_eo;
} regmatch_t;

static void usage(char *cmd) {
  printf("\n");
  printf("Print matching patterns within a file.\n");
  printf("\n");
  printf("Usage: %s -e <pattern> -o <sub string> [<path>]\n", cmd);
  printf("\n");
  printf("Summary\n");
  printf("%s is a simple tool to search patterns within files.\n", cmd);
  printf("It uses regular expressions to find patterns and prints the\n");
  printf("submatches within a pre-defined format string.\n");
  printf("\n");
  printf("Options\n");
  printf("  -e <pattern>\n");
  printf("     Specifes the search pattern.\n");
  printf("  -o <string>\n");
  printf("     Defines the output string where $0-$9 are substituted by the\n");
  printf("     submatches of the regular expression.\n");
  printf("  <path>\n");
  printf("     Defines the input file to process. %s reads from\n", cmd);
  printf("     from standard input if this parameter is omitted.\n");
  printf("\n");
  printf("Example (shows the IP addresses of clients causing mod_qos(031) messages):\n");
  printf(" %s -e 'mod_qos\\(031\\).*, c=([0-9.]*)' -o 'ip=$1' error_log\n", cmd);
  printf("\n");
  printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
  exit(1);
}

char *qs_pregsub(apr_pool_t *pool, const char *input,
		 const char *source, size_t nmatch,
		 regmatch_t pmatch[]) {
  const char *src = input;
  char *dest, *dst;
  char c;
  size_t no;
  int len;
  if(!source) {
    return NULL;
  }
  if(!nmatch) {
    return apr_pstrdup(pool, src);
  }
  /* First pass, find the size */  
  len = 0;
  while((c = *src++) != '\0') {
    if(c == '&')
      no = 0;
    else if (c == '$' && apr_isdigit(*src))
      no = *src++ - '0';
    else
      no = 10;
    
    if (no > 9) {                /* Ordinary character. */
      if (c == '\\' && (*src == '$' || *src == '&'))
	src++;
      len++;
    }
    else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
      len += pmatch[no].rm_eo - pmatch[no].rm_so;
    }
    
  }
  dest = dst = apr_pcalloc(pool, len + 1);
  /* Now actually fill in the string */
  src = input;
  while ((c = *src++) != '\0') {
    if (c == '&')
      no = 0;
    else if (c == '$' && apr_isdigit(*src))
      no = *src++ - '0';
    else
      no = 10;

    if (no > 9) {                /* Ordinary character. */
      if (c == '\\' && (*src == '$' || *src == '&'))
	c = *src++;
      *dst++ = c;
    }
    else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
      len = pmatch[no].rm_eo - pmatch[no].rm_so;
      memcpy(dst, source + pmatch[no].rm_so, len);
      dst += len;
    }
  }
  *dst = '\0';
  return dest;
}

int qs_regexec(pcre *preg, const char *string,
	       apr_size_t nmatch, regmatch_t pmatch[]) {
  int rc;
  int options = 0;
  int *ovector = NULL;
  int small_ovector[POSIX_MALLOC_THRESHOLD * 3];
  int allocated_ovector = 0;
  if (nmatch > 0) {
    if (nmatch <= POSIX_MALLOC_THRESHOLD) {
      ovector = &(small_ovector[0]);
    } else {
      ovector = (int *)malloc(sizeof(int) * nmatch * 3);
      if (ovector == NULL) {
	return 1;
      }
      allocated_ovector = 1;
    }
  }
  rc = pcre_exec(preg, NULL, string, (int)strlen(string), 0, options, ovector, nmatch * 3);
  if (rc == 0) rc = nmatch;    /* All captured slots were filled in */
  if (rc >= 0) {
    apr_size_t i;
    for (i = 0; i < (apr_size_t)rc; i++) {
      pmatch[i].rm_so = ovector[i*2];
      pmatch[i].rm_eo = ovector[i*2+1];
    }
    if (allocated_ovector) free(ovector);
    for (; i < nmatch; i++) pmatch[i].rm_so = pmatch[i].rm_eo = -1;
    return 0;
  } else {
    if (allocated_ovector) free(ovector);
    return rc;
  }
}

int main(int argc, const char * const argv[]) {
  int nr = 0;
  char line[32768];
  FILE *file = 0;
  apr_pool_t *pool;
  char *cmd = strrchr(argv[0], '/');
  const char *out = NULL;
  const char *pattern = NULL;
  const char *filename = NULL;
  pcre *preg;
  int nsub;
  const char *errptr = NULL;
  int erroffset;
  regmatch_t regm[MAX_REG_MATCH];
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-e") == 0) {
      if (--argc >= 1) {
	pattern = *(++argv);
      } 
    } else if(strcmp(*argv,"-o") == 0) {
      if (--argc >= 1) {
	out = *(++argv);
      }
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd);
    } else {
      filename = *argv;
    }
    argc--;
    argv++;
  }

  if(pattern == NULL || out == NULL) {
    usage(cmd);
  }

  preg = pcre_compile(pattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(!preg) {
    fprintf(stderr, "ERROR, could not compile '%s' at position %d, reason: %s\n",
	    pattern, erroffset, errptr);
    exit(1);
  }
  nsub = pcre_info((const pcre *)preg, NULL, NULL);

  if(filename) {
    file = fopen(filename, "r");
    if(!file) {
      fprintf(stderr, "ERROR, could not open file\n");
      exit(1);
    }
  } else {
    file = stdin;
  }
    
  while(fgets(line, sizeof(line), file) != NULL) {
    nr++;
    if(qs_regexec(preg, line, MAX_REG_MATCH, regm) == 0) {
      char *replaced = qs_pregsub(pool, out, line, MAX_REG_MATCH, regm);
      if(!replaced) {
	fprintf(stderr, "ERROR, failed to substitute submatches (line=%d)\n", nr);
      } else {
	printf("%s\n", replaced);
      }
      apr_pool_clear(pool);
    }
  }

  if(filename) {
    fclose(file);
  }
  apr_pool_destroy(pool);
  return 0;
}
