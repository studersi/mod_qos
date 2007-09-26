/**
 * Filter utilities for the quality of service module mod_qos
 * used to create white list rules for request line filters.
 *
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2007 Pascal Buchbinder
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

static const char revision[] = "$Id: qsfilter.c,v 1.1 2007-09-26 17:07:15 pbuchbinder Exp $";

#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

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

#define QS_UNRESERVED        "a-zA-Z0-9-\\._~% "
#define QS_GEN               ":/\\?#\\[\\]@"
#define QS_SUB               "!$&'\\(\\)\\*\\+,;="

#define QS_PATH_PCRE         "(/["QS_UNRESERVED"]+)*"
#define QS_CHAR_PCRE         "["QS_UNRESERVED"]"
#define QS_CHAR_GEN_PCRE     "["QS_UNRESERVED""QS_GEN"]"
#define QS_CHAR_GENSUB_PCRE  "["QS_UNRESERVED""QS_GEN""QS_SUB"]"
#define QS_OVECCOUNT 3

static int m_verbose = 1;

char *qos_extract(apr_pool_t *pool, char **line, int *ovector, int *len) {
  char *path = *line;
  char *substring_start = path + ovector[0];
  int substring_length = ovector[1] - ovector[0];
  char *rule = apr_psprintf(pool, "%.*s", substring_length, substring_start);
  *len = substring_length;
  printf(" match at %d: %s\n", ovector[0], rule);
  *line = path + substring_length;
  return rule;
}

int qos_hex2c(const char *x) {
  int i, ch;
  ch = x[0];
  if (isdigit(ch)) {
    i = ch - '0';
  }else if (isupper(ch)) {
    i = ch - ('A' - 10);
  } else {
    i = ch - ('a' - 10);
  }
  i <<= 4;
  
  ch = x[1];
  if (isdigit(ch)) {
    i += ch - '0';
  } else if (isupper(ch)) {
    i += ch - ('A' - 10);
  } else {
    i += ch - ('a' - 10);
  }
  return i;
}

static int qos_unescaping(char *x) {
  int i, j, ch;
  if (x[0] == '\0')
    return 0;
  for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
    ch = x[i];
    if (ch == '%' && isxdigit(x[i + 1]) && isxdigit(x[i + 2])) {
      ch = qos_hex2c(&x[i + 1]);
      i += 2;
    }
    x[j] = ch;
  }
  x[j] = '\0';
  return j;
}

int qs_getLine(char *s, int n) {
  int i = 0;
  while (1) {
    s[i] = (char)getchar();
    if(s[i] == EOF) return 0;
    if (s[i] == CR) {
      s[i] = getchar();
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
      s[i] = '\0';
      return 1;
    }
    ++i;
  }
}

static char *qos_query(apr_pool_t *pool, apr_pool_t *lpool, apr_table_t *rules, char *line) {
  return NULL;
}
static char *qos_path(apr_pool_t *pool, apr_pool_t *lpool, apr_table_t *rules, char *line) {
  char *rule;
  char *path = line;
  int ovector[QS_OVECCOUNT];
  const char *errptr = NULL;
  int erroffset;
  int rc_c, len;
  pcre *pcre_test;
  pcre *pcre_path;
  pcre *pcre_char;
  pcre *pcre_char_gen;
  pcre *pcre_char_gensub;

  pcre_char = pcre_compile(QS_CHAR_PCRE"+", PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre_char == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  pcre_path = pcre_compile(QS_PATH_PCRE, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);;
  if(pcre_path == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  pcre_char_gen = pcre_compile(QS_CHAR_GEN_PCRE"+", PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);;
  if(pcre_char_gen == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  pcre_char_gensub = pcre_compile(QS_CHAR_GENSUB_PCRE"+", PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);;
  if(pcre_char_gensub == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }

  qos_unescaping(path);
  
  rc_c = pcre_exec(pcre_path, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
  if((rc_c >= 0) && (ovector[0] == 0)) {
    rule = apr_psprintf(lpool, "%s", qos_extract(lpool, &path, ovector, &len));
  } else {
    fprintf(stderr, "ERROR, no valid path: %s\n", path);
    exit(1);
  }
  while(path && path[0]) {
    char *add;
    rc_c = pcre_exec(pcre_char, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
    if((rc_c >= 0) && (ovector[0] == 0)) {
      add = qos_extract(lpool, &path, ovector, &len);
      rule = apr_psprintf(lpool,"%s%s{%d}", rule, QS_CHAR_PCRE, len);
    } else {
      rc_c = pcre_exec(pcre_char_gen, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
      if((rc_c >= 0) && (ovector[0] == 0)) {
	add = qos_extract(lpool, &path, ovector, &len);
	rule = apr_psprintf(lpool,"%s%s{%d}", rule, QS_CHAR_GEN_PCRE, len);
      } else {
	rc_c = pcre_exec(pcre_char_gensub, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
	if((rc_c >= 0) && (ovector[0] == 0)) {
	  add = qos_extract(lpool, &path, ovector, &len);
	  rule = apr_psprintf(lpool,"%s%s{%d}", rule, QS_CHAR_GENSUB_PCRE, len);
	} else {
	  /* special char */
	  printf(" special char: %.*s\n", 1, path);
	  path++;
	}
      }
    }
    path = NULL;
  }
  printf(" rule: %s\n", rule);
  /* test */
  pcre_test = pcre_compile(apr_pstrcat(lpool, "^", rule, "$", NULL),
			   PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);;
  if(pcre_test == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  rc_c = pcre_exec(pcre_test, NULL, line, strlen(line), 0, 0, ovector, QS_OVECCOUNT);
  if(rc_c < 0) {
    fprintf(stderr, "ERRRO, rule does not match");
    exit(1);
  } else {
    printf(" OK\n");
  }
  pcre_free(pcre_test);
  pcre_free(pcre_path);
  pcre_free(pcre_char);
  pcre_free(pcre_char_gen);
  pcre_free(pcre_char_gensub);
  return rule;
}

int main(int argc, const char * const argv[]) {
  char line[MAX_LINE];
  apr_pool_t *pool;
  apr_table_t *rules;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  rules = apr_table_make(pool, 10);
  nice(10);
  while(qs_getLine(line, sizeof(line))) {
    char *query_rule;
    char *rule;
    apr_uri_t parsed_uri;
    apr_pool_t *lpool;
    apr_pool_create(&lpool, NULL);
    if(apr_uri_parse(pool, line, &parsed_uri) != APR_SUCCESS) {
      fprintf(stderr, "ERROR, could parse uri %s\n", line);
      exit(1);
    }
    if(m_verbose)
      printf("ANALYSE: path=%s query=%s\n",
	     parsed_uri.path,
	     parsed_uri.query == NULL ? "" : parsed_uri.query);
    rule = qos_path(pool, lpool, rules, parsed_uri.path);
    if(parsed_uri.query) {
      query_rule = qos_query(pool, lpool, rules, parsed_uri.query);
      rule = apr_pstrcat(lpool, rule, "\?", query_rule, NULL);
    }
    apr_pool_destroy(lpool);
  }
  printf("--------------------------------\n");
  apr_pool_destroy(pool);
  return 0;
}
