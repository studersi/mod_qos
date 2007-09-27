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

static const char revision[] = "$Id: qsfilter.c,v 1.11 2007-09-27 10:54:49 pbuchbinder Exp $";

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

/* reserved: {}[]()^$.|*+?\ */

#define QS_UNRESERVED        "a-zA-Z0-9-\\._~% "
#define QS_GEN               ":/\\?#\\[\\]@"
#define QS_SUB               "!$&'\\(\\)\\*\\+,;="

#define QS_PATH_PCRE         "(/["QS_UNRESERVED"]+)*"
#define QS_FUZZY_PCRE        "(/[a-zA-Z0-9-_]+)*[/]?\\.?[a-zA-Z]{0,4}"
#define QS_FUZZY_QUERY_PCRE  "([a-zA-Z0-9-_]+=[a-zA-Z0-9-_]+)(&[a-zA-Z0-9-_]+=[a-zA-Z0-9-_]+)*"
#define QS_CHAR_PCRE         "["QS_UNRESERVED"]"
#define QS_CHAR_GEN_PCRE     "["QS_UNRESERVED""QS_GEN"]"
#define QS_CHAR_GENSUB_PCRE  "["QS_UNRESERVED""QS_GEN""QS_SUB"]"
#define QS_OVECCOUNT 3

#define QS_QUERY_PCRE        "(["QS_UNRESERVED"]+(=["QS_UNRESERVED"]+)?)*"

static int m_verbose = 0;
static int m_strict = 2;

char *qos_extract(apr_pool_t *pool, char **line, int *ovector, int *len) {
  char *path = *line;
  char *substring_start = path + ovector[0];
  int substring_length = ovector[1] - ovector[0];
  char *rule = apr_psprintf(pool, "%.*s", substring_length, substring_start);
  *len = substring_length;
  if(m_verbose > 1)
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

static int qs_fgetline(char *s, int n, FILE *f) {
  register int i = 0;
  while (1) {
    s[i] = (char) fgetc(f);
    if (s[i] == CR) {
      s[i] = fgetc(f);
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
      s[i] = '\0';
      return (feof(f) ? 1 : 0);
    }
    ++i;
  }
}

static int qs_getLine(char *s, int n) {
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

static void usage(char *cmd) {
  printf("\n");
  printf("Utility to generate mod_qos request line rules out from\n");
  printf("existing access log data.\n");
  printf("\n");
  printf("Usage: %s [-c <conf>] [-s 0|1|2] [-v 0|1|2]\n", cmd);
  printf("\n");
  printf("Options\n");
  printf("  -c <conf>\n");
  printf("     mod_qos configuration file defining QS_DenyRequestLine directives,\n");
  printf("     These rules filter the input data\n");
  printf("  -s <level>\n");
  printf("     Defines how strict the rules should be (0=highest security)\n");
  printf("  -v <level>\n");
  printf("     Verbose mode.\n");
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  printf("\n");
  exit(1);
}

static int qos_enforce_blacklist(apr_table_t *rules, const char *line) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  if((line == 0) || (strlen(line) == 0)) return 0;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    pcre *p = (pcre *)entry[i].val;
    if(pcre_exec(p, NULL, line, strlen(line), 0, 0, NULL, 0) == 0) {
      if(m_verbose > 1)
	printf(" blacklist match, rule %s\n", entry[i].key);
      return 1;
    }
  }
  return 0;
}

static void qos_load_blacklist(apr_pool_t *pool, apr_table_t *blacklist, const char *httpdconf) {
  FILE *f = fopen(httpdconf, "r");
  char line[MAX_LINE];
  if(f == NULL) {
    fprintf(stderr, "ERROR, could not open %s\n", httpdconf);
    exit(1);
  }
  while(!qs_fgetline(line, sizeof(line), f)) {
    // QS_DenyRequestLine '+'|'-'<id> 'log'|'deny' <pcre>
    char *p = strstr(line, "QS_DenyRequestLine");
    if(p && (strchr(line, '#') == NULL)) {
      p = strchr(p, ' ');
      if(p) {
	while(p[0] == ' ') p++;
	p = strchr(p, ' ');
	if(p) {
	  while(p[0] == ' ') p++;
	  p = strchr(p, ' ');
	  if(p) {
	    while(p[0] == ' ') p++;
	    if(m_verbose > 1) {
	      printf("load %s\n", p);
	    }
	    {
	      const char *errptr = NULL;
	      int erroffset;
	      char *pattern = apr_psprintf(pool, "%.*s", strlen(p)-2, &p[1]);
	      pcre *pcre_test = pcre_compile(pattern, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
	      if(pcre_test == NULL) {
		fprintf(stderr, "ERROR, rule <%s> could not compile pcre at position %d,"
			" reason: %s\n", pattern, erroffset, errptr);
		exit(1);
	      }
	      apr_table_addn(blacklist, pattern, (char *)pcre_test);
	    }
	  }
	}
      }
    }
  }
  fclose(f);
}

static char *qos_build_pattern(apr_pool_t *lpool, const char *line,
			       const char *base_pattern, const char *fuzzy_pattern) {
  char *rule;
  char *path = apr_pstrdup(lpool, line);
  char *orig = path;
  int ovector[QS_OVECCOUNT];
  const char *errptr = NULL;
  int erroffset;
  int rc_c, len;
  pcre *pcre_test;
  pcre *pcre_base;
  pcre *pcre_fuzzy;
  pcre *pcre_char;
  pcre *pcre_char_gen;
  pcre *pcre_char_gensub;

  pcre_fuzzy = pcre_compile(fuzzy_pattern, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre_fuzzy == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }

  pcre_base = pcre_compile(base_pattern, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre_base == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }

  pcre_char = pcre_compile(QS_CHAR_PCRE"+", PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre_char == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  pcre_char_gen = pcre_compile(QS_CHAR_GEN_PCRE"+", PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre_char_gen == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  pcre_char_gensub = pcre_compile(QS_CHAR_GENSUB_PCRE"+", PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre_char_gensub == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }

  qos_unescaping(path);
  
  rc_c = pcre_exec(pcre_fuzzy, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
  if(m_strict && (rc_c >= 0) && (ovector[0] == 0) && ((ovector[1] - ovector[0]) == strlen(path))) {
    int substring_length = ovector[1] - ovector[0];
    rule = apr_psprintf(lpool, "%s", fuzzy_pattern);
    path = path + substring_length;
    if(m_verbose > 1) printf(" fuzzy match\n");
  } else {
    rc_c = pcre_exec(pcre_base, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
    if((rc_c >= 0) && (ovector[0] == 0)) {
      rule = apr_psprintf(lpool, "%s", qos_extract(lpool, &path, ovector, &len));
    } else {
      fprintf(stderr, "ERROR, no valid path: %s\n", path);
      exit(1);
    }
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
	  rule = apr_psprintf(lpool,"%s%s{0,%d}", rule, QS_CHAR_GENSUB_PCRE, len);
	} else {
	  /* special char */
	  if(m_verbose > 1)
	    printf(" special char: %.*s\n", 1, path);
	  if(strchr("{}^|\"\'\\", path[0]) != NULL) {
	    rule = apr_psprintf(lpool,"%s\\%.*s", rule, 1, path);
	  } else {
	    rule = apr_psprintf(lpool,"%s%.*s", rule, 1, path);
	  }
	  path++;
	}
      }
    }
  }
  if(m_verbose > 1)
    printf(" rule: %s\n", rule);
  /* test */
  pcre_test = pcre_compile(apr_pstrcat(lpool, "^", rule, "$", NULL),
			   PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre_test == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  rc_c = pcre_exec(pcre_test, NULL, orig, strlen(orig), 0, 0, ovector, QS_OVECCOUNT);
  if(rc_c < 0) {
    fprintf(stderr, "ERRRO, rule does not match!\n");
    fprintf(stderr, "line %s\n", line);
    fprintf(stderr, "string: %s\n", orig);
    fprintf(stderr, "rule: %s\n", rule);
    exit(1);
  }
  pcre_free(pcre_test);
  pcre_free(pcre_base);
  pcre_free(pcre_char);
  pcre_free(pcre_char_gen);
  pcre_free(pcre_char_gensub);
  return rule;
}

int qos_test_for_existing_rule(char *line, apr_table_t *rules) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  if((line == 0) || (strlen(line) == 0)) return 0;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    pcre *p = (pcre *)entry[i].val;
    if(pcre_exec(p, NULL, line, strlen(line), 0, 0, NULL, 0) >= 0) {
      if(m_verbose > 1)
	printf(" exsiting rule %s\n", entry[i].key);
      return 1;
    }
  }
  return 0;
}

int main(int argc, const char * const argv[]) {
  int line_nr = 0;
  int deny_count = 0;
  char line[MAX_LINE];
  apr_pool_t *pool;
  apr_table_t *rules;
  apr_table_t *blacklist;
  char *cmd = strrchr(argv[0], '/');
  const char *httpdconf = NULL;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  rules = apr_table_make(pool, 10);
  blacklist = apr_table_make(pool, 10);
  nice(10);
  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-v") == 0) {
      if (--argc >= 1) {
	m_verbose = atoi(*(++argv));
      } 
    } else if(strcmp(*argv,"-s") == 0) {
      if (--argc >= 1) {
	m_strict = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-c") == 0) {
      if (--argc >= 1) {
	httpdconf = *(++argv);
      }
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd);
    }
    argc--;
    argv++;
  }

  if(httpdconf) {
    qos_load_blacklist(pool, blacklist, httpdconf);
  }

  while(qs_getLine(line, sizeof(line))) {
    char *query_rule;
    char *rule;
    apr_uri_t parsed_uri;
    apr_pool_t *lpool;
    char *line_test;
    int deny = 0;
    line_nr++;
    apr_pool_create(&lpool, NULL);
    if(apr_uri_parse(pool, line, &parsed_uri) != APR_SUCCESS) {
      fprintf(stderr, "ERROR, could parse uri %s\n", line);
      exit(1);
    }
    if(parsed_uri.path == NULL) {
      fprintf(stderr, "WARNING, line %d: invalid request %s\n", line_nr, line);
    } else {
      if(m_verbose > 1) {
	printf("--------------------------------\n");
	printf("ANALYSE: path=%s query=%s\n",
	       parsed_uri.path,
	       parsed_uri.query == NULL ? "" : parsed_uri.query);
      }
      line_test = apr_pstrdup(lpool, line);
      qos_unescaping(line_test);

      if(qos_enforce_blacklist(blacklist, line_test)) {
	fprintf(stderr, "WARNING: blacklist filter at line %d for %s\n", line_nr, line);
	deny = 1;
	deny_count++;
      }

      if(!qos_test_for_existing_rule(line_test, rules) && !deny) {
	const char *prev;
	const char *errptr = NULL;
	int erroffset;
	pcre *pcre_test;
	rule = qos_build_pattern(lpool, parsed_uri.path, QS_PATH_PCRE, QS_FUZZY_PCRE);
	if(parsed_uri.query) {
	  query_rule = qos_build_pattern(lpool, parsed_uri.query, QS_QUERY_PCRE, QS_FUZZY_QUERY_PCRE);
	  rule = apr_pstrcat(lpool, "^", rule, "\\?", query_rule, "$", NULL);
	} else {
	  rule = apr_pstrcat(lpool, "^", rule, "$", NULL);
	}
	
	pcre_test = pcre_compile(rule, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
	if(pcre_test == NULL) {
	  fprintf(stderr, "ERROR, rule <%s> could not compile pcre at position %d,"
		  " reason: %s\n", rule, erroffset, errptr);
	  exit(1);
	}
	if(pcre_exec(pcre_test, NULL, line_test, strlen(line_test), 0, 0, NULL, 0) < 0) {
	  fprintf(stderr, "ERRRO, rule does not match!\n");
	  fprintf(stderr, "line %d: %s\n", line_nr, line);
	  fprintf(stderr, "string: %s\n", line_test);
	  fprintf(stderr, "rule: %s\n", rule);
	  exit(1);
	} else {
	  if(m_verbose > 1)
	    printf(" RULE: %s\n", rule);
	}
	//pcre_free(pcre_test);
	prev = apr_table_get(rules, rule);
	if(prev == NULL) {
	  apr_table_addn(rules, apr_pstrdup(pool, rule), (char *)pcre_test);
	  if(m_verbose) {
	    printf("# ADD line %d: %s\n", line_nr, line);
	    printf("#     rule %s\n", rule);
	  }
	}
      }
    }
    apr_pool_destroy(lpool);
  }

  {
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
    printf("\n# --------------------------------------------------------\n");
    printf("# %d rules from %d access log lines\n", apr_table_elts(rules)->nelts, line_nr);
    printf("#  strict mode: %d\n", m_strict);
    printf("#  filtered lines: %d\n", deny_count);
    printf("# --------------------------------------------------------\n");
    for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
      printf("QS_PermitUri +QSF%0.3d deny \"%s\"\n", i, entry[i].key);
    }
  }
  apr_pool_destroy(pool);
  
  return 0;
}
