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

static const char revision[] = "$Id: qsgrep.c,v 1.4 2012-01-26 09:58:22 pbuchbinder Exp $";

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

#include "qs_util.h"

#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif
#define MAX_REG_MATCH 10

typedef struct {
    int rm_so;
    int rm_eo;
} regmatch_t;

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
  qs_man_print(man, "Print matching patterns within a file.\n");
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -e <pattern> -o <sub string> [<path>]\n", man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "%s is a simple tool to search patterns within files.\n", cmd);
  qs_man_print(man, "It uses regular expressions to find patterns and prints the\n");
  qs_man_print(man, "submatches within a pre-defined format string.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -e <pattern>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifes the search pattern.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -o <string>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the output string where $0-$9 are substituted by the\n");
  qs_man_print(man, "     submatches of the regular expression.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  <path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the input file to process. %s reads from\n", cmd);
  qs_man_print(man, "     from standard input if this parameter is omitted.\n");
  printf("\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
    qs_man_println(man, "Shows the IP addresses of clients causing mod_qos(031) messages):\n");
    printf("\n");
  } else {
    printf("Example (shows the IP addresses of clients causing mod_qos(031) messages):\n");
  }
  qs_man_println(man, "  %s -e 'mod_qos\\(031\\).*, c=([0-9.]*)' -o 'ip=$1' error_log\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsexec(1), qsfilter2(1), qslog(1), qspng(1), qsrotate(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://opensource.adnovum.ch/mod_qos/\n");
  } else {
    printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
  }
  if(man) {
    exit(0);
  } else {
    exit(1);
  }
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
  int rc;
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
      usage(cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    } else {
      filename = *argv;
    }
    argc--;
    argv++;
  }

  if(pattern == NULL || out == NULL) {
    usage(cmd, 0);
  }

  rc = nice(10);

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
