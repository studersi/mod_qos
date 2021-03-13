/**
 * qsfilter.c: Filter utilities for the quality of service module mod_qos
 * used to create allow list rules for request line filters.
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2021 Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

static const char revision[] = "$Id$";

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

#define QS_CHAR_PCRE          "["QS_UNRESERVED"]"
#define QS_CHAR_GEN_PCRE      "["QS_UNRESERVED""QS_GEN"]"
#define QS_CHAR_GENSUB_PCRE   "["QS_UNRESERVED""QS_GEN""QS_SUB"]"
#define QS_CHAR_GENSUB_S_PCRE "["QS_UNRESERVED""QS_GEN""QS_SUB_S"]"

#define QS_PATH_PCRE          "(/["QS_UNRESERVED"]+)+"
#define QS_FUZZY_PCRE         "(/[a-zA-Z0-9-_]+)+[/]?\\.?[a-zA-Z]{0,4}"

#define QS_QUERY_PCRE_pre     "[&]?["QS_UNRESERVED"]+(=["QS_UNRESERVED"\\$]+)?"
//#define QS_QUERY_PCR        "([&]?["QS_UNRESERVED"]+(=["QS_UNRESERVED"\\$]+)?)+"
#define QS_QUERY_PCRE         "("QS_QUERY_PCRE_pre")+"
#define QS_FUZZY_QUERY_PCRE   "([a-zA-Z0-9-_]+=[a-zA-Z0-9-_]+)(&[a-zA-Z0-9-_]+=[a-zA-Z0-9-_]+)*"

#define QS_B64                "([a-z]+[a-z0-9]*[A-Z]+[A-Z0-9]*)"

#define QS_OVECCOUNT 3

static int m_verbose = 1;
static int m_strict = 2;
static int m_base64 = 5;
static int m_redundant = 0;
static int m_nq = 0;

pcre *pcre_char;
pcre *pcre_char_gen;
pcre *pcre_char_gensub;
pcre *pcre_char_gensub_s;
pcre *pcre_b64;

typedef struct {
  pcre *pcre;
  pcre_extra *extra;
} qs_rule_t;

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

static char *qos_detect_b64(char *line) {
  int ovector[QS_OVECCOUNT];
  int rc_c = pcre_exec(pcre_b64, NULL, line, strlen(line), 0, 0, ovector, QS_OVECCOUNT);
  if(rc_c >= 0) {
    if(m_verbose > 1) printf("  B64: %.*s\n", ovector[1] - ovector[0], &line[ovector[0]]);
    return &line[ovector[0]];
  }
  return NULL;
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
  printf("Usage: %s -i <path> [-c <path>] [-s 0|1|2|3|4] [-b <num>] [-o] [-v 0|1|2]\n", cmd);
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
  printf("  -s <level>\n");
  printf("     Defines how strict the rules should be (0=very high, 1=high, 2=high\n");
  printf("     to medium, 3=medium, 4=low).\n");
  printf("     Default is 2 which provides a compact and performant rule set.\n");
  printf("     Level 1 is recommended for selected locations.\n");
  printf("  -b <num>\n");
  printf("     Replaces url pattern by the regular expression when detecting a\n");
  printf("     base64 encoded string. Detecting sensibility is defined by a numeric\n");
  printf("     value. You should use values higher than 5 (default) or 0 to disable\n");
  printf("     this function.\n");
  printf("  -o\n");
  printf("     Eliminates redundant rules (may take long time but is recommended).\n");
  printf("     Default is off.\n");
  printf("     This feature is only available if the configuratin file (-c)\n");
  printf("     does not contain any QS_PermitUri directives since this would\n");
  printf("     eliminate these existing rules.\n");
  printf("  -v <level>\n");
  printf("     Verbose mode. (0=silent, 1=rule source, 2=detailed). Default is 1.\n");
  printf("     Don't use rules you haven't checked the request data used to\n");
  printf("     generate it! Level 1 is highly recommended (as long as you don't\n");
  printf("     want to check every line of your access log data).\n");
  printf("  -x\n");
  printf("     Enable all \"experimental\" stuff.\n");
  printf("\n");
  printf("Example\n");
  printf("  ./%s -i loc.txt -o -s 1 -c httpd.conf\n", cmd);
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  printf("mod_qos, "__DATE__"\n");
  exit(1);
}

static int qos_enforce_denylist(apr_table_t *rules, const char *line) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  if((line == 0) || (strlen(line) == 0)) return 0;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    qs_rule_t *rs = (qs_rule_t *)entry[i].val;
    if(pcre_exec(rs->pcre, rs->extra, line, strlen(line), 0, 0, NULL, 0) == 0) {
      if(m_verbose > 1) printf(" deny list match, rule %s\n", entry[i].key);
      return 1;
    }
  }
  return 0;
}

static void qos_load_rules(apr_pool_t *pool, apr_table_t *ruletable,
			   const char *httpdconf, const char *command,
			   int option) {
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
	      int erroffset;
	      char *pattern;
	      pcre *pcre_test;
	      pcre_extra *extra;
	      qs_rule_t *rs;
	      if(p[0] = '"') {
		pattern = apr_psprintf(pool, "%.*s", strlen(p)-2, &p[1]);
	      } else {
		pattern = apr_psprintf(pool, "%.*s", strlen(p), p);
	      }
	      pcre_test = pcre_compile(pattern, PCRE_DOTALL|option, &errptr, &erroffset, NULL);
	      if(pcre_test == NULL) {
		fprintf(stderr, "ERROR, rule <%s> could not compile pcre at position %d,"
			" reason: %s\n", pattern, erroffset, errptr);
		exit(1);
	      }
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

static void qos_load_denylist(apr_pool_t *pool, apr_table_t *denylist, const char *httpdconf) {
  qos_load_rules(pool, denylist, httpdconf, "QS_DenyRequestLine", PCRE_CASELESS);
}
static void qos_load_allowlist(apr_pool_t *pool, apr_table_t *rules, const char *httpdconf) {
  qos_load_rules(pool, rules, httpdconf, "QS_PermitUri", 0);
}

static char *qos_build_pattern(apr_pool_t *lpool, const char *line,
			       const char *base_pattern, const char *fuzzy_pattern,
			       qs_url_type_e type) {
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

  pcre_fuzzy = pcre_compile(fuzzy_pattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(pcre_fuzzy == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }

  pcre_base = pcre_compile(base_pattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(pcre_base == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }

  qos_unescaping(path);
  if(m_verbose > 1) printf(" IN %s\n", path);

  /* strict levels:
   * 0, matching pattern (url only), no fuzzy, reduced charset
   * 1, matching pattern (partial, url only), no fuzzy, reduced charset
   * 2, matching pattern (url only) and fuzzy pcre, reduced charset
   * 3, pcre (url and query) and fuzzy pcre
   * 4, rounded string length
   */

  /*
   * start either with the fuzzy (takes the pcre) or base pattern (takes the match)
   */  
  rc_c = pcre_exec(pcre_fuzzy, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
  if((m_strict > 1) && (rc_c >= 0) && (ovector[0] == 0) && ((ovector[1] - ovector[0]) == strlen(path))) {
    int substring_length = ovector[1] - ovector[0];
    rule = apr_psprintf(lpool, "%s", fuzzy_pattern);
    path = path + substring_length;
    if(m_verbose > 1) printf(" fuzzy %d match: %s\n", m_strict, rule);
  } else {
    rc_c = pcre_exec(pcre_base, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
    if((rc_c >= 0) && (ovector[0] == 0) && (ovector[1] - ovector[0])) {
      if((m_strict > 2) || (type == QS_UT_QUERY)) {
	int substring_length = ovector[1] - ovector[0];
	rule = apr_psprintf(lpool, "%s", base_pattern);
	path = path + substring_length;
	if(m_verbose > 1) printf(" base %d match: %s\n", m_strict, rule);
      } else {
	char *b64;
	rule = apr_psprintf(lpool, "%s", qos_extract(lpool, &path, ovector, &len, "base"));
	if(m_strict > 0) {
	  char *end = strrchr(rule, '/');
	  if(end && (end > rule) && (end < &rule[strlen(rule)-1])) {
	    end[0] = '\0';
	    rule = apr_psprintf(lpool, "%s%.*s{1}", rule, strlen(base_pattern)-1, base_pattern);
	  }
	}
	b64 = qos_detect_b64(rule);
	if(b64 && m_base64) {
	  /* don't use this pattern match if it contains a base64 string */
	  printf("# NOTE, base64 detection in string %s\n", rule);
	  b64[0] = '\0';
	  if((strlen(rule) > 3) && strrchr(&rule[1], '/')) {
	    char *sub = strrchr(&rule[1], '/');
	    sub[0] = '\0';
	    rule = apr_psprintf(lpool, "%s%s", rule, base_pattern);
	  } else {
	    rule = apr_psprintf(lpool, "%s", base_pattern);
	  }
	}
      }
    } else {
      fprintf(stderr, "ERROR, no valid path: %s\n", path);
      exit(1);
    }
  }
  /*
   * iterate through all patterns (base, char, char gen, char gen sub, ..., special)
   */
  while(path && path[0]) {
    char *add = NULL;
    int slen;
    rc_c = pcre_exec(pcre_base, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
    if((rc_c >= 0) && (ovector[0] == 0)) {
      add = qos_extract(lpool, &path, ovector, &len, "base'");
      if((m_strict > 2) || (type == QS_UT_QUERY)) {
	rule = apr_psprintf(lpool,"%s%s", rule, base_pattern);
      } else {
	if(qos_detect_b64(rule) && m_base64) {
	  /* don't use this pattern match if it contains a base64 string */
	  printf("# NOTE, base64 detection in string: %s\n", rule);
	  rule = apr_psprintf(lpool, "%s%s", rule, base_pattern);
	} else {
	  rule = apr_psprintf(lpool,"%s%s", rule, add);
	}
      }
    } else {
      rc_c = pcre_exec(pcre_char, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
      if((rc_c >= 0) && (ovector[0] == 0)) {
	add = qos_extract(lpool, &path, ovector, &len, "char");
	slen = len;
	if(m_strict > 3) slen = ((slen / 10) + 1) * 10;
	rule = apr_psprintf(lpool,"%s%s{1,%d}", rule, QS_CHAR_PCRE, slen);
      } else {
	rc_c = pcre_exec(pcre_char_gen, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
	if((rc_c >= 0) && (ovector[0] == 0)) {
	  add = qos_extract(lpool, &path, ovector, &len, "gen");
	  slen = len;
	  if(m_strict > 3) slen = ((slen / 10) + 1) * 10;
	  rule = apr_psprintf(lpool,"%s%s{1,%d}", rule, QS_CHAR_GEN_PCRE, slen);
	} else {
	  rc_c = pcre_exec(pcre_char_gensub, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
	  if((rc_c >= 0) && (ovector[0] == 0) && (m_strict > 2)) {
	    add = qos_extract(lpool, &path, ovector, &len, "sub");
	    slen = len;
	    if(m_strict > 3) slen = ((slen / 10) + 1) * 10;
	    rule = apr_psprintf(lpool,"%s%s{1,%d}", rule, QS_CHAR_GENSUB_PCRE, slen);
	  } else {
	    rc_c = pcre_exec(pcre_char_gensub_s, NULL, path, strlen(path), 0, 0, ovector, QS_OVECCOUNT);
	    if((rc_c >= 0) && (ovector[0] == 0)) {
	      add = qos_extract(lpool, &path, ovector, &len, "sub'");
	      slen = len;
	      if(m_strict > 3) slen = ((slen / 10) + 1) * 10;
	      rule = apr_psprintf(lpool,"%s%s{1,%d}", rule, QS_CHAR_GENSUB_S_PCRE, slen);
	    } else {
	      unsigned char *ch = (unsigned char *)path;
	      /* special char */
	      if(m_verbose > 1) printf(" special char: %.*s\n", 1, path);
	      if(strchr("{}[]()^$.|*+?\"'\\", ch[0]) != NULL) {
		rule = apr_psprintf(lpool,"%s\\%.*s", rule, 1, path);
	      } else if((ch[0] < ' ') || (ch[0]  > '~')) {
		rule = apr_psprintf(lpool, "%s\\x%02x", rule, ch[0]);
	      } else {
		rule = apr_psprintf(lpool,"%s%.*s", rule, 1, path);
	      }
	      path++;
	    }
	  }
	}
      }
    }
  }
  if(m_verbose > 1) printf(" => rule: %s\n", rule);
  /* test */
  pcre_test = pcre_compile(apr_pstrcat(lpool, "^", rule, "$", NULL),
			   PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(pcre_test == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  rc_c = pcre_exec(pcre_test, NULL, orig, strlen(orig), 0, 0, ovector, QS_OVECCOUNT);
  if(rc_c < 0) {
    fprintf(stderr, "ERROR, rule does not match!\n");
    fprintf(stderr, "line %s\n", line);
    fprintf(stderr, "string: %s\n", orig);
    fprintf(stderr, "rule: %s\n", rule);
    exit(1);
  }
  pcre_free(pcre_test);
  pcre_free(pcre_base);
  return rule;
}

int qos_test_for_existing_rule(char *line, apr_table_t *rules) {
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

static void qos_init_pcre() {
  const char *errptr = NULL;
  int erroffset;
  pcre_char = pcre_compile(QS_CHAR_PCRE"+", PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(pcre_char == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  pcre_char_gen = pcre_compile(QS_CHAR_GEN_PCRE"+", PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(pcre_char_gen == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  pcre_char_gensub = pcre_compile(QS_CHAR_GENSUB_PCRE"+", PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(pcre_char_gensub == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  pcre_char_gensub_s = pcre_compile(QS_CHAR_GENSUB_S_PCRE"+", PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(pcre_char_gensub_s == NULL) {
    fprintf(stderr, "ERROR, could not compile pcre at position %d,"
	    " reason: %s\n", erroffset, errptr);
    exit(1);
  }
  {
    char buf[1024];
    sprintf(buf, "%s{%d,}", QS_B64, m_base64);
    pcre_b64 = pcre_compile(buf, PCRE_DOTALL, &errptr, &erroffset, NULL);
    if(pcre_b64 == NULL) {
      fprintf(stderr, "ERROR, could not compile pcre %s at position %d,"
	      " reason: %s\n", buf, erroffset, errptr);
      exit(1);
    }
  }
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

static void qos_delete_non_query(apr_pool_t *pool, apr_table_t *rules) {
#define QS_QUERY_PCRE_P "\\?"QS_QUERY_PCRE"$"
  apr_table_t *remove = apr_table_make(pool, 1);
  apr_table_t *add = apr_table_make(pool, 1);
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    if(strlen(entry[i].key) > strlen(QS_QUERY_PCRE_P)) {
      char *q = &entry[i].key[strlen(entry[i].key)-strlen(QS_QUERY_PCRE_P)];
      if(strcmp(q, QS_QUERY_PCRE_P) == 0) {
	char *s = apr_psprintf(pool, "%.*s$", q - entry[i].key, entry[i].key);
	if(apr_table_get(rules, s)) {
	  qs_rule_t *rs;
	  const char *errptr = NULL;
	  int erroffset;
	  char *new_rule = entry[i].key;
	  if(m_verbose) printf("# CHANGE <%s> to ", new_rule);
	  rs = (qs_rule_t *)entry[i].val;
	  apr_table_add(remove, s, "1");
	  apr_table_add(remove, entry[i].key, "2");
	  s[strlen(s)-1] = '\0';
	  new_rule = apr_pstrcat(pool, s, "(\\?"QS_QUERY_PCRE_pre")*$", NULL);
	  if(m_verbose) printf("<%s>\n", new_rule);
	  rs->pcre = pcre_compile(new_rule, PCRE_DOTALL, &errptr, &erroffset, NULL);
	  rs->extra = pcre_study(rs->pcre, 0, &errptr);
	  apr_table_addn(add, new_rule, (char *)rs);
	}
      }
    }
  }
  entry = (apr_table_entry_t *)apr_table_elts(remove)->elts;
  for(i = 0; i < apr_table_elts(remove)->nelts; i++) {
    apr_table_unset(rules, entry[i].key);
  }
  entry = (apr_table_entry_t *)apr_table_elts(add)->elts;
  for(i = 0; i < apr_table_elts(add)->nelts; i++) {
    apr_table_addn(rules, entry[i].key, entry[i].val);
  }
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
  if(m_nq) qos_delete_non_query(pool, rules);
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

static void qos_generate_rules(apr_pool_t *pool, apr_table_t *denylist, apr_table_t *rules,
			       apr_table_t *rules_url, FILE *f, int *dc, int *ln) {
  int deny_count = *dc;
  int line_nr = *ln;
  char line[MAX_LINE];
  while(!qos_fgetline(line, sizeof(line), f)) {
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

      if(qos_enforce_denylist(denylist, line_test)) {
	fprintf(stderr, "WARNING: deny list filter match at line %d for %s\n", line_nr, line);
	deny = 1;
	deny_count++;
      }
      if(!qos_test_for_existing_rule(line_test, rules) && !deny) {
	const char *prev;
	const char *errptr = NULL;
	int erroffset;
	pcre *pcre_test;
	pcre_extra *extra;
	rule = qos_build_pattern(lpool, parsed_uri.path, QS_PATH_PCRE, QS_FUZZY_PCRE, QS_UT_PATH);
	if(parsed_uri.query) {
	  query_rule = qos_build_pattern(lpool, parsed_uri.query, QS_QUERY_PCRE,
					 QS_FUZZY_QUERY_PCRE, QS_UT_QUERY);
	  rule = apr_pstrcat(lpool, "^", rule, "\\?", query_rule, "$", NULL);
	} else {
	  rule = apr_pstrcat(lpool, "^", rule, "$", NULL);
	}
	pcre_test = pcre_compile(rule, PCRE_DOTALL, &errptr, &erroffset, NULL);
	if(pcre_test == NULL) {
	  fprintf(stderr, "ERROR, rule <%s> could not compile pcre at position %d,"
		  " reason: %s\n", rule, erroffset, errptr);
	  exit(1);
	}
	extra = pcre_study(pcre_test, 0, &errptr);
	// don't mind if extra is null
	if(pcre_exec(pcre_test, extra, line_test, strlen(line_test), 0, 0, NULL, 0) < 0) {
	  fprintf(stderr, "ERRRO, rule does not match!\n");
	  fprintf(stderr, "line %d: %s\n", line_nr, line);
	  fprintf(stderr, "string: %s\n", line_test);
	  fprintf(stderr, "rule: %s\n", rule);
	  exit(1);
	} else {
	  if(m_verbose > 1) printf(" RULE: %s\n", rule);
	}
	//pcre_free(pcre_test);
	prev = apr_table_get(rules, rule);
	if(prev == NULL) {
	  qs_rule_t *rs = apr_palloc(pool, sizeof(qs_rule_t));
	  rs->pcre = pcre_test;
	  rs->extra = extra;
	  if(m_verbose) {
	    printf("# ADD line %d: %s\n", line_nr, line);
	    printf("# %0.3d rule %s\n", apr_table_elts(rules)->nelts, rule);
	    fflush(stdout);
	  }
	  apr_table_add(rules_url, line_test, "unescaped line");
	  apr_table_addn(rules, apr_pstrdup(pool, rule), (char *)rs);
	  if(apr_table_elts(rules)->nelts == 500) {
	    printf("NOTE, found %d rules - you may want to stop further processing ...\n",
		   apr_table_elts(rules)->nelts);
	  }
	  if(apr_table_elts(rules)->nelts == 1000) {
	    printf("NOTE, found %d rules - you may want to stop further processing ...\n",
		   apr_table_elts(rules)->nelts);
	    if(m_strict < 4) {
	      printf("... or increase the strict level!\n");
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
  time_t start = time(NULL);
  time_t end;
  int deny_count = 0;
  int line_nr = 0;
  const char *access_log = NULL;
  FILE *f;
  apr_pool_t *pool;
  apr_table_t *rules;
  apr_table_t *rules_url;
  apr_table_t *denylist;
  int denylist_size = 0;
  int allowlist_size = 0;
  char *cmd = strrchr(argv[0], '/');
  const char *httpdconf = NULL;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  rules = apr_table_make(pool, 10);
  rules_url = apr_table_make(pool, 10);
  denylist = apr_table_make(pool, 10);
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
    } else if(strcmp(*argv,"-i") == 0) {
      if (--argc >= 1) {
	access_log = *(++argv);
      }
    } else if(strcmp(*argv,"-b") == 0) {
      if (--argc >= 1) {
	m_base64 = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-o") == 0) {
      m_redundant = 1;
    } else if(strcmp(*argv,"-x") == 0) {
      m_nq = 1;
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
    qos_load_denylist(pool, denylist, httpdconf);
    denylist_size = apr_table_elts(denylist)->nelts;
    qos_load_allowlist(pool, rules, httpdconf);
    allowlist_size = apr_table_elts(rules)->nelts;
  }
  if(access_log == NULL) usage(cmd);
  f = fopen(access_log, "r");
  if(f == NULL) {
    fprintf(stderr, "ERROR, could not open input file %s\n", access_log);
    exit(1);
  }
  qos_generate_rules(pool, denylist, rules, rules_url, f, &deny_count, &line_nr);
  fclose(f);
  if((allowlist_size == 0) && m_redundant) {
    int x = 0;
    int y = 0;
    // delete useless rules
    qos_delete_obsolete_rules(pool, rules, rules_url);
    // ensure, we have not deleted to many!
    if(m_verbose) {
      printf("# check the result (again)\n"); 
      fflush(stdout);
    }
    f = fopen(access_log, "r");
    qos_generate_rules(pool, denylist, rules, rules_url, f, &x, &y);
    fclose(f);
  }

  {
    char *time_string;
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
    int duration;
    end = time(NULL);
    time_string = ctime(&end);
    time_string[strlen(time_string) - 1] = '\0';
    duration = (end - start) / 60;
    printf("\n# --------------------------------------------------------\n");
    printf("# %s\n", time_string);
    printf("# %d rules from %d access log lines\n", apr_table_elts(rules)->nelts, line_nr);
    printf("#  source: %s\n", access_log);
    printf("#  strict mode: %d\n", m_strict);
    printf("#  base64 detection: %d\n", m_base64);
    printf("#  redundancy check: %s\n", (m_redundant && (allowlist_size == 0)) == 1 ? "on" : "off");
    printf("#  extra mode: %d\n", m_nq);
    printf("#  rule file: %s\n", httpdconf == NULL ? "-" : httpdconf);
    printf("#    allow list (loaded existing rules): %d\n", allowlist_size);
    printf("#    deny list (loaded deny rules): %d\n", denylist_size);
    printf("#    filtered lines: %d\n", deny_count);
    printf("#  duration: %d minutes\n", duration);
    printf("# --------------------------------------------------------\n");
    for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
      printf("QS_PermitUri +QSF%0.3d deny \"%s\"\n", i+1, entry[i].key);
    }
  }
  apr_pool_destroy(pool);
  
  return 0;
}
