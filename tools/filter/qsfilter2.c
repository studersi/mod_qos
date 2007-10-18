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

static const char revision[] = "$Id: qsfilter2.c,v 1.16 2007-10-18 09:25:57 pbuchbinder Exp $";

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

#define QS_SIMPLE_PATH_PCRE   "(/[a-zA-Z0-9-_]+)+[/]?\\.?[a-zA-Z]{0,4}"
#define QS_B64                "([a-z]+[a-z0-9]*[A-Z]+[A-Z0-9]*)"

#define QS_OVECCOUNT 3

pcre *pcre_b64;
pcre *pcre_simple_path;

static int m_base64 = 5;
static int m_verbose = 1;
static int m_path_depth = 1;
static int m_redundant = 1;
static int m_query_pcre = 0;
static int m_query_single_pcre = 0;
static int m_exit_on_error = 0;

typedef struct {
  pcre *pcre;
  pcre_extra *extra;
} qs_rule_t;

static pcre *qos_pcre_compile(char *pattern, int option) {
  const char *errptr = NULL;
  int erroffset;
  pcre *pcre = pcre_compile(pattern, PCRE_DOTALL|option, &errptr, &erroffset, NULL);
  if(pcre == NULL) {
    fprintf(stderr, "ERROR, rule <%s> could not compile pcre at position %d,"
	    " reason: %s\n", pattern, erroffset, errptr);
    exit(1);
  }
  return pcre;
}

static char *qos_detect_b64(char *line, int silent) {
  int ovector[QS_OVECCOUNT];
  int rc_c = pcre_exec(pcre_b64, NULL, line, strlen(line), 0, 0, ovector, QS_OVECCOUNT);
  if(rc_c >= 0) {
    if((m_verbose > 1) && !silent) printf("  B64: %.*s\n", ovector[1] - ovector[0], &line[ovector[0]]);
    return &line[ovector[0]];
  }
  return NULL;
}

static char *qos_escape_pcre(apr_pool_t *pool, char *line) {
  int i = 0;
  unsigned char *in = (unsigned char *)line;
  char *ret = apr_pcalloc(pool, strlen(line) * 4);
  int reti = 0;
  while(in[i]) {
    if(strchr("{}[]()^$.|*+?\"'", in[i]) != NULL) {
      ret[reti] = '\\';
      reti++;
      ret[reti] = in[i];
      reti++;
    } else if((in[i] < ' ') || (in[i]  > '~')) {
      sprintf(&ret[reti], "\\x%02x", in[i]);
      reti = reti + 4;
    } else {
      ret[reti] = in[i];
      reti++;
    }
    i++;
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

static void qos_init_pcre() {
  char buf[1024];
  sprintf(buf, "%s{%d,}", QS_B64, m_base64);
  pcre_b64 = qos_pcre_compile(buf, 0);
  pcre_simple_path = qos_pcre_compile("^"QS_SIMPLE_PATH_PCRE"$", 0);
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
  printf("Usage: %s -i <path> [-c <path>] [-d <num>] [-b <num>] [-p|-s] [-n] [-e]\n", cmd);
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
  printf("  -d <num>\n");
  printf("     Depth of the path string. Default is 1.\n");
  printf("  -b <num>\n");
  printf("     Replaces url pattern by the regular expression when detecting a\n");
  printf("     base64 encoded string. Detecting sensibility is defined by a numeric\n");
  printf("     value. You should use values higher than 5 (default) or 0 to disable\n");
  printf("     this function.\n");
  printf("  -p\n");
  printf("     Uses pcre for query only.\n");
  printf("  -s\n");
  printf("     Uses one single pcre for the whole query string.\n");
  printf("  -n\n");
  printf("     Disables redundant rules elimination.\n");
  printf("  -e\n");
  printf("     Exit on error.\n");
  printf("\n");
  printf("Example\n");
  printf("  ./%s -i loc.txt -c httpd.conf\n", cmd);
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  printf("mod_qos, "__DATE__"\n");
  exit(1);
}

typedef struct {
  apr_pool_t *pool;
  apr_table_t *rules;
  apr_table_t *rules_url;
  int from;
  int to;
} qs_worker_t;

static apr_table_t *qos_get_used(apr_pool_t *pool, apr_table_t *rules, apr_table_t *rules_url,
				 int from, int to) {
  apr_table_t *used = apr_table_make(pool, 1);
  int j;
  for(j = from; j < to; j++) {
    int l;
    apr_table_entry_t *linee = (apr_table_entry_t *)apr_table_elts(rules_url)->elts;
    if(m_verbose) {
      printf("[%d]", j);
      fflush(stdout);
    }
    for(l = 0; l < apr_table_elts(rules_url)->nelts; l++) {
      char *line = linee[l].key;
      int i;
      int match = 0;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
      for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
	if(i != j) {
	  qs_rule_t *rs = (qs_rule_t *)entry[i].val;
	  if(pcre_exec(rs->pcre, rs->extra, line, strlen(line), 0, 0, NULL, 0) >= 0) {
	    match = 1;
	    break;
	  }
	}
      }
      if(!match) {
	/* no match, rule j is required */
	apr_table_add(used, entry[j].key, "+");
      }
    }
  }
  return used;
}

static void *qos_worker(void *argv) {
  qs_worker_t *wt = argv;
  return qos_get_used(wt->pool, wt->rules, wt->rules_url, wt->from, wt->to);
}

static void qos_delete_obsolete_rules(apr_pool_t *pool, apr_table_t *rules, apr_table_t *rules_url) {
  apr_table_t *not_used = apr_table_make(pool, 1);
  apr_table_t *used;
  apr_table_t *used1;
  pthread_attr_t *tha = NULL;
  pthread_t tid;
  qs_worker_t *wt = apr_pcalloc(pool, sizeof(qs_worker_t));
  wt->pool = pool;
  wt->rules = rules;
  wt->rules_url = rules_url;
  wt->from = apr_table_elts(rules)->nelts / 2;
  wt->to = apr_table_elts(rules)->nelts;
  if(m_verbose) printf("# search for redundant rules (%d/%d)\n",
		       apr_table_elts(rules_url)->nelts,
		       apr_table_elts(rules)->nelts);
  if(m_verbose) printf("# ");
  pthread_create(&tid, tha, qos_worker, (void *)wt);
  used = qos_get_used(pool, rules, rules_url, 0, apr_table_elts(rules)->nelts / 2);
  pthread_join(tid, (void *)&used1);
  if(m_verbose) printf(" done\n");
  {
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
    for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
      if((apr_table_get(used, entry[i].key) == NULL) &&
	 (apr_table_get(used1, entry[i].key) == NULL)) {
	if(m_verbose) printf("# DEL rule (not required): %s\n", entry[i].key);
	apr_table_add(not_used, entry[i].key, "-");
      }
    }
    entry = (apr_table_entry_t *)apr_table_elts(not_used)->elts;
    for(i = 0; i < apr_table_elts(not_used)->nelts; i++) {
      apr_table_unset(rules, entry[i].key);
    }
  }
}

int qos_test_for_existing_rule(char *line, apr_table_t *rules, int line_nr) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  if((line == 0) || (strlen(line) == 0)) return 0;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    qs_rule_t *rs = (qs_rule_t *)entry[i].val;
    if(pcre_exec(rs->pcre, rs->extra, line, strlen(line), 0, 0, NULL, 0) >= 0) {
      if(m_verbose > 1)	printf("LINE %d, exiting rule: %s\n", line_nr, entry[i].key);
      return 1;
    }
  }
  return 0;
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
			   const char *httpdconf, const char *command, int option) {
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
	      pcre_test = qos_pcre_compile(pattern, option);
	      extra = pcre_study(pcre_test, 0, &errptr);
	      rs = apr_palloc(pool, sizeof(qs_rule_t));
	      rs->pcre = pcre_test;
	      rs->extra = extra;
	      apr_table_setn(ruletable, pattern, (char *)rs);
	    }
	  }
	}
      }
    }
  }
  fclose(f);
}

static void qos_load_blacklist(apr_pool_t *pool, apr_table_t *blacklist, const char *httpdconf) {
  qos_load_rules(pool, blacklist, httpdconf, "QS_DenyRequestLine", PCRE_CASELESS);
}
static void qos_load_whitelist(apr_pool_t *pool, apr_table_t *rules, const char *httpdconf) {
  qos_load_rules(pool, rules, httpdconf, "QS_PermitUri", 0);
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
  int hasB = 0;
  int i = 0;
  unsigned char *in = (unsigned char *)line;
  char *ret = apr_pcalloc(pool, strlen(line) * 6);
  int reti = 0;
  while(in[i]) {
    if(isdigit(in[i])) {
      if(!hasD) {
	hasD = 1;
	strcpy(&ret[reti], "0-9");
	reti = reti + 3;
      }
    } else if(isalpha(in[i])) {
      if(!hasA) {
	hasA = 1;
	strcpy(&ret[reti], "a-zA-Z");
	reti = reti + 6;
      }
    } else if(in[i] == '\\') {
      if(!hasE) {
	hasE = 1;
	strcpy(&ret[reti], "\\\\");
	reti = reti + 2;
      }
    } else if(in[i] == '-') {
      if(!hasB) {
	hasB = 1;
	strcpy(&ret[reti], "\\-");
	reti = reti + 2;
      }
    } else if(strchr(ret, in[i]) == NULL) {
      if(strchr("{}[]()^$.|*+?\"'", in[i]) != NULL) {
	ret[reti] = '\\';
	reti++;
	ret[reti] = in[i];
	reti++;
      } else if((in[i] < ' ') || (in[i]  > '~')) {
	sprintf(&ret[reti], "\\x%02x", in[i]);
	reti = reti + 4;
      } else {
	ret[reti] = in[i];
	reti++;
      }
    }
    i++;
  }
  if(strlen(ret) == 0) return NULL;
  ret[reti] = '\0';
  return ret;
}

static char *qos_b64_2pcre(apr_pool_t *pool, const char *line) {
  char *copy = apr_pstrdup(pool, line);
  char *b64 = qos_detect_b64(copy, 1);
  char *st = b64;
  char *ed = &b64[1];
  if(m_verbose > 1) printf("  B642pcre: %s", copy);
  /* reserved: {}[]()^$.|*+?\ */
#define QS_BX "-_$+!"
  while(st[0] && (isdigit(st[0]) || isalpha(st[0]) || (strchr(QS_BX, st[0]) != NULL))) {
    st--;
  }
  st++;
  st[0] = '\0';
  while(ed[0] && (isdigit(ed[0]) || isalpha(ed[0]) || (strchr(QS_BX, ed[0]) != NULL))) {
    ed++;
  }
  if(m_verbose > 1) printf(" %s <> %s\n", copy, ed);
  return apr_pstrcat(pool, qos_escape_pcre(pool, copy),
		     "[a-zA-Z0-9\\-_\\$\\+!]+",
		     ed[0] == '\0' ? NULL : qos_escape_pcre(pool, ed), NULL);
}


// query to <string>=<pcre> or <pcre>=<pcre>
static char *qos_query_string_pcre(apr_pool_t *pool, const char *path) {
  char *copy = apr_pstrdup(pool, path);
  char *pos = copy;
  char *ret = "";
  int isValue = 0;
  int open = 0;
  while(copy[0]) {
    if(copy[0] == '=') {
      copy[0] = '\0';
      qos_unescaping(pos);
      if(!open) {
	ret = apr_pstrcat(pool, ret, "(", NULL);
	open = 1;
      }
      if(m_query_pcre) {
	ret = apr_pstrcat(pool, ret, "[", qos_2pcre(pool, pos), "]+=", NULL);
      } else {
	ret = apr_pstrcat(pool, ret, qos_escape_pcre(pool, pos), "=", NULL);
      }
      open = 1;
      pos = copy;
      pos++;
      isValue = 1;
    }
    if(copy[0] == '&') {
      copy[0] = '\0';
      if(strlen(pos) == 0) {
	ret = apr_pstrcat(pool, ret, "[&]?", NULL);
	if(open) {
	  ret = apr_pstrcat(pool, ret, ")?", NULL);
	  open = 0;
	}
      } else {
	qos_unescaping(pos);
	ret = apr_pstrcat(pool, ret, "[", qos_2pcre(pool, pos), "]+[&]?", NULL);
	if(open) {
	  ret = apr_pstrcat(pool, ret, ")?", NULL);
	  open = 0;
	}
      }
      pos = copy;
      pos++;
      isValue = 0;
    }
    copy++;
  }
  if(pos != copy) {
    qos_unescaping(pos);
    if(isValue) {
      ret = apr_pstrcat(pool, ret, "[", qos_2pcre(pool, pos), "]+", NULL);
    } else {
      if(!open) {
	ret = apr_pstrcat(pool, "(", ret, NULL);
	open = 1;
      }
      if(m_query_pcre) {
	ret = apr_pstrcat(pool, ret, "[", qos_2pcre(pool, pos), "]+", NULL);
      } else {
	ret = apr_pstrcat(pool, ret, qos_escape_pcre(pool, pos), NULL);
      }
    }
    if(open) {
      ret = apr_pstrcat(pool, ret, ")?", NULL);
      open = 0;
    }
  }
  if(open) {
    ret = apr_pstrcat(pool, ret, ")?", NULL);
    open = 0;
  }
  return ret;
}

// path to <pcre>
static char *qos_path_pcre(apr_pool_t *lpool, const char *path) {
  char *dec = apr_pstrdup(lpool, path);
  qos_unescaping(dec);
  return apr_pstrcat(lpool, "[", qos_2pcre(lpool, dec), "]+", NULL);
}

// path to <pcre>/<string>
static char *qos_path_pcre_string(apr_pool_t *lpool, const char *path) {
  int nohandler = 0;
  char *lpath = apr_pstrdup(lpool, path);
  char *last;
  char *str = "";
  int depth = m_path_depth;
  char *rx = "";
  if(lpath[strlen(lpath)-1] == '/') {
    lpath[strlen(lpath)-1] = '\0';
    nohandler = 1;
  }
  last = strrchr(lpath, '/');
  while(last && depth) {
    if(m_base64 && qos_detect_b64(last, 0)) {
      str = apr_pstrcat(lpool, qos_b64_2pcre(lpool, last), str, NULL);
    } else {
      str = apr_pstrcat(lpool, qos_escape_pcre(lpool, last), str, NULL);
    }
    last[0] = '\0';
    last = strrchr(lpath, '/');
    depth--;
  }
  if(lpath[0]) {
    qos_unescaping(lpath);
    rx = apr_pstrcat(lpool, "[", qos_2pcre(lpool, lpath), "]+", NULL);
  }
  if(strlen(str) > 0) {
    qos_unescaping(str);
    if(nohandler) {
      rx = apr_pstrcat(lpool, rx, str, "[/]?", NULL);
    } else {
      rx = apr_pstrcat(lpool, rx, str, NULL);
    }
  }
  return rx;
}

static void qos_process_log(apr_pool_t *pool, apr_table_t *blacklist, apr_table_t *rules,
			    apr_table_t *rules_url, FILE *f, int *ln, int *dc) {
  char line[MAX_LINE];
  int deny_count = *dc;
  int line_nr = *ln;
  while(!qos_fgetline(line, sizeof(line), f)) {
    apr_uri_t parsed_uri;
    apr_pool_t *lpool;
    apr_pool_create(&lpool, NULL);
    line_nr++;
    if(apr_uri_parse(lpool, line, &parsed_uri) != APR_SUCCESS) {
      fprintf(stderr, "ERROR, could parse uri %s\n", line);
      if(m_exit_on_error) exit(1);
    }
    if(parsed_uri.path == NULL || (parsed_uri.path[0] != '/')) {
      fprintf(stderr, "WARNING, line %d: invalid request %s\n", line_nr, line);
    } else {
      char *path = NULL;
      char *query = NULL;
      char *fragment = NULL;
      char *copy = apr_pstrdup(lpool, line);
      qos_unescaping(copy);
      if(qos_enforce_blacklist(blacklist, copy)) {
	fprintf(stderr, "WARNING: blacklist filter match at line %d for %s\n",
		line_nr, line);
	deny_count++;
      } else {
	if(!qos_test_for_existing_rule(copy, rules, line_nr)) {
	  if(m_verbose > 1) printf("LINE %d, analyse: %s\n", line_nr, line);
	  if(parsed_uri.query) {
	    if(strcmp(parsed_uri.path, "/") == 0) {
	      path = apr_pstrdup(lpool, "/");
	    } else {
	      path = qos_path_pcre_string(lpool, parsed_uri.path);
	    }
	    if(m_query_single_pcre) {
	      char *qc = apr_pstrdup(lpool, parsed_uri.query);
	      qos_unescaping(qc);
	      query = apr_pstrcat(lpool, "[", qos_2pcre(lpool, qc), "]+", NULL);
	    } else {
	      query = qos_query_string_pcre(lpool, parsed_uri.query);
	    }
	  } else {
	    if(strcmp(parsed_uri.path, "/") == 0) {
	      path = apr_pstrdup(lpool, "/");
	    } else {
	      if(pcre_exec(pcre_simple_path, NULL, parsed_uri.path, strlen(parsed_uri.path), 0, 0, NULL, 0) >= 0) {
		path = apr_pstrdup(lpool, QS_SIMPLE_PATH_PCRE);
	      } else {
		path = qos_path_pcre(lpool, parsed_uri.path);
	      }
	    }
	  }
	  if(parsed_uri.fragment) {
	    char *f = apr_pstrdup(lpool, parsed_uri.fragment);
	    qos_unescaping(f);
	    fragment = apr_pstrcat(lpool, "[", qos_2pcre(lpool, f), "]+", NULL);
	  }
	  if(m_verbose > 1) {
	    printf(" path:      %s\n", parsed_uri.path);
	    printf(" path rule: %s\n", path);
	    if(query) {
	      printf(" query:      %s\n", parsed_uri.query);
	      printf(" query rule: %s\n", query);
	    }
	    if(fragment) {
	      printf(" fragment:      %s\n", parsed_uri.fragment);
	      printf(" fragment rule: %s\n", fragment);
	    }
	  }
	  {
	    const char *errptr = NULL;
	    char *rule = apr_pstrcat(pool, "^", path, NULL);
	    qs_rule_t *rs = apr_palloc(pool, sizeof(qs_rule_t));
	    if(query) {
	      rule = apr_pstrcat(pool, rule, "\\?", query, NULL);
	    }
	    if(fragment) {
	      rule = apr_pstrcat(pool, rule, "#", fragment, NULL);
	    }
	    rule = apr_pstrcat(pool, rule, "$", NULL);
	    rs->pcre = qos_pcre_compile(rule, 0);
	    rs->extra = pcre_study(rs->pcre, 0, &errptr);
	    // don't mind if extra is null
	    if(m_verbose) {
	      printf("# ADD line %d: %s\n", line_nr, line);
	      printf("# %0.3d %s\n", apr_table_elts(rules)->nelts+1, rule);
	      fflush(stdout);
	    }
	    if(pcre_exec(rs->pcre, rs->extra, copy, strlen(copy), 0, 0, NULL, 0) < 0) {
	      fprintf(stderr, "ERROR, rule check failed (did not match)!\n");
	      fprintf(stderr, " line %d: %s\n", line_nr, line);
	      fprintf(stderr, " string: %s\n", copy);
	      fprintf(stderr, " rule: %s\n", rule);
	      if(m_exit_on_error) exit(1);
	    } else {
	      apr_table_add(rules_url, copy, "unescaped line");
	      apr_table_setn(rules, rule, (char *)rs);
	    }
	  }
	}
      }
    }
    apr_pool_destroy(lpool);
  }
  *dc = deny_count;
  *ln = line_nr;
}

int main(int argc, const char * const argv[]) {
  apr_table_entry_t *entry;
  time_t start = time(NULL);
  time_t end;
  int line_nr = 0;
  int deny_count = 0;
  char *time_string;
  int i;
  const char *access_log = NULL;
  FILE *f;
  apr_pool_t *pool;
  apr_table_t *rules;
  apr_table_t *blacklist;
  apr_table_t *rules_url;
  int blacklist_size = 0;
  int whitelist_size = 0;
  char *cmd = strrchr(argv[0], '/');
  const char *httpdconf = NULL;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  rules = apr_table_make(pool, 10);
  blacklist = apr_table_make(pool, 10);
  rules_url = apr_table_make(pool, 10);
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
    } else if(strcmp(*argv,"-d") == 0) {
      if (--argc >= 1) {
	m_path_depth = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-n") == 0) {
      m_redundant = 0;
    } else if(strcmp(*argv,"-b") == 0) {
      if (--argc >= 1) {
	m_base64 = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-p") == 0) {
      m_query_pcre = 1;
    } else if(strcmp(*argv,"-s") == 0) {
      m_query_single_pcre = 1;
    } else if(strcmp(*argv,"-e") == 0) {
      m_exit_on_error = 1;
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
  qos_init_pcre();

  if(httpdconf) {
    qos_load_blacklist(pool, blacklist, httpdconf);
    blacklist_size = apr_table_elts(blacklist)->nelts;
    qos_load_whitelist(pool, rules, httpdconf);
    whitelist_size = apr_table_elts(rules)->nelts;
  }

  if(access_log == NULL) usage(cmd);
  f = fopen(access_log, "r");
  if(f == NULL) {
    fprintf(stderr, "ERROR, could not open input file %s\n", access_log);
    exit(1);
  }
  qos_process_log(pool, blacklist, rules, rules_url, f, &line_nr, &deny_count);
  fclose(f);

  if(m_redundant) {
    int x = 0;
    int y = 0;
    // delete useless rules
    qos_delete_obsolete_rules(pool, rules, rules_url);
    // ensure, we have not deleted to many!
    if(m_verbose) {
      printf("# check the result (again)\n"); 
      fflush(stdout);
    }
    if(httpdconf) {
      qos_load_whitelist(pool, rules, httpdconf);
    }
    f = fopen(access_log, "r");
    qos_process_log(pool, blacklist, rules, rules_url, f, &x, &y);
    fclose(f);
  }

  end = time(NULL);
  time_string = ctime(&end);
  time_string[strlen(time_string) - 1] = '\0';
  printf("\n# --------------------------------------------------------\n");
  printf("# %s\n", time_string);
  printf("# %d rules from %d access log lines\n", apr_table_elts(rules)->nelts, line_nr);
  printf("#  source: %s\n", access_log);
  printf("#  path depth: %d\n", m_path_depth);
  printf("#  base64 detection level: %d\n", m_base64);
  printf("#  redundancy check: %s\n", m_redundant == 1 ? "on" : "off");
  printf("#  pcre in query: %s\n", m_query_pcre == 1 ? "yes" : "no");
  printf("#  single pcre for query: %s\n", m_query_single_pcre == 1 ? "yes" : "no");
  printf("#  exit on error: %s\n", m_exit_on_error == 1 ? "yes" : "no");
  printf("#  rule file: %s\n", httpdconf == NULL ? "-" : httpdconf);
  if(httpdconf) {
    printf("#    white list (loaded existing rules): %d\n", whitelist_size);
    printf("#    black list (loaded deny rules): %d\n", blacklist_size);
    printf("#    black list matches: %d\n", deny_count);
  }
  printf("#  duration: %d minutes\n", (end - start) / 60);
  printf("# --------------------------------------------------------\n");
  
  entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    printf("QS_PermitUri +QSF%0.3d deny \"%s\"\n", i+1, entry[i].key);
  }
  apr_pool_destroy(pool);
  
  return 0;
}
