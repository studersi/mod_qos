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

static const char revision[] = "$Id: qsrule.c,v 1.2 2007-10-04 19:45:53 pbuchbinder Exp $";

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

typedef enum  {
  QS_UT_PATH,
  QS_UT_QUERY
} qs_url_type_e;

#define QS_UNRESERVED         "a-zA-Z0-9-\\._~% "
#define QS_GEN                ":/\\?#\\[\\]@"
#define QS_SUB                "!$&'\\(\\)\\*\\+,;="
#define QS_SUB_S              "!$&\\(\\)\\*\\+,;="

#define QS_OVECCOUNT 3

static int m_verbose = 1;

typedef struct {
  pcre *pcre;
  pcre_extra *extra;
} qs_rule_t;

static pcre *qos_pcre_compile(char *pattern) {
  const char *errptr = NULL;
  int erroffset;
  pcre *pcre = pcre_compile(pattern, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pcre == NULL) {
    fprintf(stderr, "ERROR, rule <%s> could not compile pcre at position %d,"
	    " reason: %s\n", pattern, erroffset, errptr);
    exit(1);
  }
  return pcre;
}

static char *qos_escape_pcre(apr_pool_t *pool, char *line) {
  char *ret = apr_pcalloc(pool, strlen(line) * 2);
  int i = 0;
  int j = 0;
  while(line[i]) {
    if(strchr("{}[]()^$.|*+?\"'\\", line[i]) != NULL) {
      ret[j] = '\\';
      j++;
    }
    ret[j] = line[i];
    i++;
    j++;
  }
  return ret;
}

static char *qos_extract(apr_pool_t *pool, char **line, int *ovector, int *len, const char *pn) {
  char *path = *line;
  char *substring_start = path + ovector[0];
  int substring_length = ovector[1] - ovector[0];
  char *rule = apr_psprintf(pool, "%.*s", substring_length, substring_start);
  *len = substring_length;
  if(m_verbose > 1) printf(" %s, match at %d: %s\n", pn, ovector[0], rule);
  *line = path + substring_length;
  return qos_escape_pcre(pool, rule);
}

static int qos_hex2c(const char *x) {
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

static int qos_fgetline(char *s, int n, FILE *f) {
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

static int qos_getline(char *s, int n) {
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
  printf("Usage: %s -i <path> [-c <path>]\n", cmd);
  printf("\n");
  printf("Summary\n");
  printf("%s is an access log analyzer used to generate filter rules (perl\n", cmd);
  printf("compatible regular expressions) which may be used with mod_qos to\n");
  printf("deny access for suspect request lines. The input format must\n");
  printf("contain a single request URI (path and query) on each line.\n");
  printf("\n");
  printf("Options\n");
  printf("  -i <path>\n");
  printf("     Request url (path and query) from the access log (one request per line).\n");
  printf("  -c <path>\n");
  printf("     mod_qos configuration file defining QS_DenyRequestLine and\n");
  printf("     QS_PermitUri directives.\n");
  printf("\n");
  printf("Example\n");
  printf("  ./%s -i loc.txt -c httpd.conf\n", cmd);
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  printf("mod_qos, "__DATE__"\n");
  exit(1);
}

static int qos_enforce_blacklist(apr_table_t *rules, const char *line) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  if((line == 0) || (strlen(line) == 0)) return 0;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    qs_rule_t *rs = (qs_rule_t *)entry[i].val;
    if(pcre_exec(rs->pcre, rs->extra, line, strlen(line), 0, 0, NULL, 0) == 0) {
      if(m_verbose > 1) printf(" blacklist match, rule %s\n", entry[i].key);
      return 1;
    }
  }
  return 0;
}

static void qos_load_rules(apr_pool_t *pool, apr_table_t *ruletable,
			       const char *httpdconf, const char *command) {
  FILE *f = fopen(httpdconf, "r");
  char line[MAX_LINE];
  if(f == NULL) {
    fprintf(stderr, "ERROR, could not open %s\n", httpdconf);
    exit(1);
  }
  while(!qos_fgetline(line, sizeof(line), f)) {
    // QS_DenyRequestLine '+'|'-'<id> 'log'|'deny' <pcre>
    char *p = strstr(line, command);
    if(p) {
      p[0] = '\0';
      p++;
    }
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
	      char *pattern;
	      pcre *pcre_test;
	      pcre_extra *extra;
	      qs_rule_t *rs;
	      if(p[0] = '"') {
		pattern = apr_psprintf(pool, "%.*s", strlen(p)-2, &p[1]);
	      } else {
		pattern = apr_psprintf(pool, "%.*s", strlen(p), p);
	      }
	      pcre_test = qos_pcre_compile(pattern);
	      extra = pcre_study(pcre_test, 0, &errptr);
	      rs = apr_palloc(pool, sizeof(qs_rule_t));
	      rs->pcre = pcre_test;
	      rs->extra = extra;
	      apr_table_addn(ruletable, pattern, (char *)rs);
	    }
	  }
	}
      }
    }
  }
  fclose(f);
}

static void qos_load_blacklist(apr_pool_t *pool, apr_table_t *blacklist, const char *httpdconf) {
  qos_load_rules(pool, blacklist, httpdconf, "QS_DenyRequestLine");
}
static void qos_load_whitelist(apr_pool_t *pool, apr_table_t *rules, const char *httpdconf) {
  qos_load_rules(pool, rules, httpdconf, "QS_PermitUri");
}

int qos_test_for_matching_rule(char *line, apr_table_t *rules) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  if((line == 0) || (strlen(line) == 0)) return 0;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    qs_rule_t *rs = (qs_rule_t *)entry[i].val;
    if(pcre_exec(rs->pcre, rs->extra, line, strlen(line), 0, 0, NULL, 0) >= 0) {
      if(m_verbose > 1)	printf(" exsiting rule %s\n", entry[i].key);
      return 1;
    }
  }
  return 0;
}

static char *qos_2pcre(apr_pool_t *pool, const char *line) {
  int hasA = 0;
  int hasD = 0;
  int hasE = 0;
  int i = 0;
  char *ret = apr_pcalloc(pool, sizeof(line) * 2);
  int reti = 0;
  while(line[i]) {
    int ch = line[i];
    if(isdigit(ch)) {
      if(!hasD) {
	hasD = 1;
	strcpy(&ret[reti], "0-9");
	reti = reti + 3;
      }
    } else if(isalpha(ch)) {
      if(!hasA) {
	hasA = 1;
	strcpy(&ret[reti], "a-zA-Z");
	reti = reti + 6;
      }
    } else if(ch == '\\') {
      if(!hasE) {
	hasE = 1;
	strcpy(&ret[reti], "\\\\");
	reti = reti + 2;
      }
    } else if(strchr(ret, ch) == NULL) {
      if(strchr("{}[]()^$.|*+?\"'\\", line[i]) != NULL) {
	ret[reti] = '\\';
	reti++;
      }
      ret[reti] = ch;
      reti++;
    }
    i++;
  }
  if(strlen(ret) == 0) return NULL;
  return ret;
}


int main(int argc, const char * const argv[]) {
  apr_table_entry_t *entry;
  time_t start = time(NULL);
  time_t end;
  char *time_string;
  int i;
  const char *access_log = NULL;
  FILE *f;
  apr_pool_t *pool;
  apr_table_t *rules;
  apr_table_t *blacklist;
  int blacklist_size = 0;
  int whitelist_size = 0;
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
    } else if(strcmp(*argv,"-c") == 0) {
      if (--argc >= 1) {
	httpdconf = *(++argv);
      }
    } else if(strcmp(*argv,"-i") == 0) {
      if (--argc >= 1) {
	access_log = *(++argv);
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
    blacklist_size = apr_table_elts(blacklist)->nelts;
    qos_load_whitelist(pool, rules, httpdconf);
    whitelist_size = apr_table_elts(rules)->nelts;
  }
  /*
  if(access_log == NULL) usage(cmd);
  f = fopen(access_log, "r");
  if(f == NULL) {
    fprintf(stderr, "ERROR, could not open input file %s\n", access_log);
    exit(1);
  }
  fclose(f);
  */
  /* $$$ */
  {
    char line[MAX_LINE];
    while(qos_getline(line, sizeof(line))) {
      char *pattern = qos_2pcre(pool, line);
      printf("I: %s\n", line);
      printf("R: %s\n", pattern == NULL ? "-" : pattern);
    }
  }


  end = time(NULL);
  time_string = ctime(&end);
  time_string[strlen(time_string) - 1] = '\0';
  printf("\n# --------------------------------------------------------\n");
  printf("# %s\n", time_string);
  printf("#  source: %s\n", access_log);
  printf("#  rule file: %s\n", httpdconf == NULL ? "-" : httpdconf);
  printf("#    white list (loaded existing rules): %d\n", whitelist_size);
  printf("#    black list (loaded deny rules): %d\n", blacklist_size);
  printf("#  duration: %d minutes\n", (end - start) / 60);
  printf("# --------------------------------------------------------\n");

  entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    printf("QS_PermitUri +QSF%0.3d deny \"%s\"\n", i+1, entry[i].key);
  }
  apr_pool_destroy(pool);
  
  return 0;
}
