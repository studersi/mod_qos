/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */
/**
 * Filter utilities for the quality of service module mod_qos
 * used to create white list rules for request line filters.
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2019 Pascal Buchbinder
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

/* system */
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <pcre.h>

/* apr */
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
//#include <ap_config.h>

/* OpenSSL  */
#include <openssl/safestack.h>

#include "qs_util.h"

#define MAX_LINE 32768
/* 2mb */
#define MAX_BODY_BUFFER 2097152
#define CR 13
#define LF 10

typedef enum  {
  QS_UT_PATH,
  QS_UT_QUERY
} qs_url_type_e;

#define QS_PCRE_RESERVED      "{}[]()^$.|*+?\\-"
//#define QS_PCRE_RESERVED      "{}[]()^$.|*+?\"'\\-"

/* reserved (to be escaped): {}[]()^$.|*+?\- */
#define QS_UNRESERVED         "a-zA-Z0-9-\\._~% "
#define QS_GEN                ":/\\?#\\[\\]@"
#define QS_SUB                "!$&'\\(\\)\\*\\+,;="
#define QS_SUB_S              "!$&\\(\\)\\*\\+,;="

#define QS_SIMPLE_PATH_PCRE   "(/[a-zA-Z0-9\\-_]+)+[/]?\\.?[a-zA-Z]{0,4}"
#define QS_B64                "([a-z]+[a-z0-9]*[A-Z]+[A-Z0-9]*)"
#define QS_HX                 "([A-F0-9]*[A-F]+[0-9]+[A-F0-9]*)"

#define QS_OVECCOUNT 3

/* request line detection */
#define QOSC_REQ          "(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|BCOPY|BDELETE|BMOVE|BPROPFIND|BPROPPATCH|NOTIFY|POLL|SUBSCRIBE|UNSUBSCRIBE|X-MS-ENUMATTS|RPC_IN_DATA|RPC_OUT_DATA) /[\x20-\x21\x23-\xFF]* HTTP/"

pcre *pcre_b64;
pcre *pcre_hx;
pcre *pcre_simple_path;

#define QOS_DEC_MODE_FLAGS_URL        0x00
#define QOS_DEC_MODE_FLAGS_HTML       0x01
#define QOS_DEC_MODE_FLAGS_UNI        0x02
#define QOS_DEC_MODE_FLAGS_ANSI       0x04

/* global variables to store settings */
static int m_mode = QOS_DEC_MODE_FLAGS_URL;
static int m_base64 = 5;
static int m_verbose = 1;
static int m_path_depth = 1;
static int m_redundant = 1;
static int m_query_pcre = 0;
static int m_query_multi_pcre = 0;
static int m_query_o_pcre = 0;
static int m_query_single_pcre = 0;
static int m_query_len_pcre = 10;
static int m_exit_on_error = 0;
static int m_handler = 0;
static pcre *m_req_regex = NULL;
static int m_log_req_regex = 0;
static const char *m_pfx = NULL;
static const char *m_filter = NULL;

typedef struct {
  pcre *pcre;
  pcre_extra *extra;
  char *rule;
  char *path;
  char *query_m_string;
  char *query_m_pcre;
  int fragment;
} qs_rule_t;


/* openssl stack compare function used to sort the rules */
int STACK_qs_cmp(const char * const *_pA, const char * const *_pB) {
  qs_rule_t *pA=*(( qs_rule_t **)_pA);
  qs_rule_t *pB=*(( qs_rule_t **)_pB);
  return strcmp(pA->rule,pB->rule);
}

/* compiles a pcre (exit on error) */
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

/* tries to detect base64/hex patterns (mix of upper and lower case characters) */
static char *qos_detect_b64(char *line, int silent) {
  int ovector[QS_OVECCOUNT];
  int rc_c = pcre_exec(pcre_b64, NULL, line, strlen(line), 0, 0, ovector, QS_OVECCOUNT);
  if(rc_c >= 0) {
    if((m_verbose > 1) && !silent) printf("  B64: %.*s\n",
                                          ovector[1] - ovector[0], &line[ovector[0]]);
    return &line[ovector[0]];
  }
  rc_c = pcre_exec(pcre_hx, NULL, line, strlen(line), 0, 0, ovector, QS_OVECCOUNT);
  if(rc_c >= 0) {
    if((m_verbose > 1) && !silent) printf("  HX: %.*s\n",
                                          ovector[1] - ovector[0], &line[ovector[0]]);
    return &line[ovector[0]];
  }
  return NULL;
}

/* escape double quotes and backslash (to be used for Apache directive) */
static char *qs_apache_escape(apr_pool_t *pool, const char *line) {
  char *ret = apr_pcalloc(pool, strlen(line) * 4);
  int i = 0;
  const char *in = line;
  while(in && in[0]) {
    if(in[0] == '"') {
      ret[i] = '\\';
      i++;
      ret[i] = 'x';
      i++;
      ret[i] = '2';
      i++;
      ret[i] = '2';
      i++;
    } else if(in[0] == '\\' && in[1] == '\\') {
      ret[i] = '\\';
      i++;
      ret[i] = 'x';
      i++;
      ret[i] = '5';
      i++;
      ret[i] = 'c';
      i++;
      in++;
    } else {
      ret[i] = (char)in[0];
      i++;
    }
    in++;
  }
  return ret;
}

/* escape a string in order to be used withn a pcre */
static char *qos_escape_pcre(apr_pool_t *pool, char *line) {
  int i = 0;
  unsigned char prev = 0;
  unsigned char *in = (unsigned char *)line;
  char *ret = apr_pcalloc(pool, strlen(line) * 4);
  int reti = 0;
  if(strlen(line) == 0) return "";
  while(in[i]) {
    if(strchr(QS_PCRE_RESERVED, in[i]) != NULL) {
      if(prev && (prev == '\\')) {
        /* already escaped */
        ret[reti] = in[i];
        reti++;
      } else if(prev && (in[i] == '\\') && (strchr(QS_PCRE_RESERVED, in[i+1]) != NULL)) {
        /* escape char */
        ret[reti] = in[i];
        reti++;
      } else {
        ret[reti] = '\\';
        reti++;
        ret[reti] = in[i];
        reti++;
      }
    } else if((in[i] < ' ') || (in[i]  > '~')) {
      sprintf(&ret[reti], "\\x%02x", in[i]);
      reti = reti + 4;
    } else {
      ret[reti] = in[i];
      reti++;
    }
    prev = in[i];
    i++;
  }
  return ret;
}

/* helper for url decoding */
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

static int qos_ishex(char x) {
  if((x >= '0') && (x <= '9')) return 1;
  if((x >= 'a') && (x <= 'f')) return 1;
  if((x >= 'A') && (x <= 'F')) return 1;
  return 0;
}

/* url decoding */
static int qos_unescaping(char *x) {
  int i, j, ch;
  if (x[0] == '\0')
    return 0;
  for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
    ch = x[i];
    if(ch == '%' && qos_ishex(x[i + 1]) && qos_ishex(x[i + 2])) {
      ch = qos_hex2c(&x[i + 1]);
      i += 2;
    } else if((m_mode & QOS_DEC_MODE_FLAGS_UNI) && 
              ((ch == '%') || (ch == '\\')) &&
              ((x[i + 1] == 'u') || (x[i + 1] == 'U')) &&
              qos_ishex(x[i + 2]) &&
              qos_ishex(x[i + 3]) &&
              qos_ishex(x[i + 4]) &&
              qos_ishex(x[i + 5])) {
      /* unicode %uXXXX */
      ch = qos_hex2c(&x[i + 4]);
      if((ch > 0x00) && (ch < 0x5f) &&
         ((x[i + 2] == 'f') || (x[i + 2] == 'F')) &&
         ((x[i + 3] == 'f') || (x[i + 3] == 'F'))) {
        ch += 0x20;
      }
      i += 5;
    } else if (ch == '\\' && (x[i + 1] == 'x') && qos_ishex(x[i + 2]) && qos_ishex(x[i + 3])) {
      ch = qos_hex2c(&x[i + 2]);
      i += 3;
    } else if (ch == '+') {
      ch = ' ';
    }
    x[j] = ch;
  }
  x[j] = '\0';
  if(strlen(x) != j) {
    fprintf(stderr, "WARNING, found escaped null char %s\n", x);
  }
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

/* init global pcre */
static void qos_init_pcre() {
  char buf[1024];
  sprintf(buf, "%s{%d,}", QS_B64, m_base64);
  pcre_b64 = qos_pcre_compile(buf, 0);
  sprintf(buf, "%s{%d,}", QS_HX, m_base64);
  pcre_hx = qos_pcre_compile(buf, 0);
  pcre_simple_path = qos_pcre_compile("^"QS_SIMPLE_PATH_PCRE"$", 0);
  m_req_regex = qos_pcre_compile(QOSC_REQ, 0);
}

static void usage(char *cmd, int man) {
  char space[1024];
  memset(space, ' ', 1024);
  space[strlen(cmd)] = '\0';
  if(man) {
    //.TH [name of program] [section number] [center footer] [left footer] [center header]
    printf(".TH %s 1 \"%s\" \"mod_qos utilities %s\" \"%s man page\"\n", qs_CMD(cmd), man_date,
           man_version, cmd);
  }
  printf("\n");
  if(man) {
    printf(".SH NAME\n");
  }
  qs_man_print(man, "%s - an utility to generate mod_qos request line rules out from\n",
               cmd);
  qs_man_print(man, "existing access/audit log data.\n");
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -i <path> [-c <path>] [-d <num>] [-h] [-b <num>]\n", man ? "" : "Usage: ", cmd);
  qs_man_print(man, "       %s [-p|-s|-m|-o] [-l <len>] [-n] [-e] [-u 'uni']\n", space);
  qs_man_print(man, "       %s [-k <prefix>] [-t] [-f <path>] [-v 0|1|2]\n", space);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, " mod_qos implements a request filter which validates each request\n");
  qs_man_print(man, " line. The module supports both, negative and positive security\n");
  qs_man_print(man, " model. The QS_Deny* directives are used to specify request line\n");
  qs_man_print(man, " patterns which are not allowed to access the server (negative\n");
  qs_man_print(man, " security model / blacklist). These rules are used to restrict\n");
  qs_man_print(man, " access to certain resources which should not be available to\n");
  qs_man_print(man, " users or to protect the server from malicious patterns. The\n");
  qs_man_print(man, " QS_Permit* rules implement a positive security model (whitelist).\n");
  qs_man_print(man, " These directives are used to define allowed request line patterns.\n");
  qs_man_print(man, " Request which do not match any of thses patterns are not allowed\n");
  qs_man_print(man, " to access the server.\n");
  if(man) printf("\n\n");
  qs_man_print(man, " %s is an audit log analyzer used to generate filter\n", cmd);
  qs_man_print(man, " rules (perl compatible regular expressions) which may be used\n");
  qs_man_print(man, " by mod_qos to deny access for suspect requests (QS_PermitUri rules).\n");
  qs_man_print(man, " It parses existing audit log files in order to generate request\n");
  qs_man_print(man, " patterns covering all allowed requests.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -i <path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Input file containing request URIs.\n");
  qs_man_print(man, "     The URIs for this file have to be extracted from the servers\n");
  qs_man_print(man, "     access logs. Each line of the input file contains a request\n");
  qs_man_print(man, "     URI consiting of a path and and query.\n");
  printf("\n");
  printf("     Example:\n");
  qs_man_println(man, "       /aaa/index.do\n");
  qs_man_println(man, "       /aaa/edit?image=1.jpg\n");
  qs_man_println(man, "       /aaa/image/1.jpg\n");
  qs_man_println(man, "       /aaa/view?page=1\n");
  qs_man_println(man, "       /aaa/edit?document=1\n");
  printf("\n");
  qs_man_print(man, "     These access log data must include current request URIs but\n");
  qs_man_print(man, "     also request lines from previous rule generation steps. It\n");
  qs_man_print(man, "     must also include request lines which cover manually generated\n");
  qs_man_print(man, "     rules.\n");
  qs_man_print(man, "     You may use the 'qos-path' and 'qos-query' variables to create\n");
  qs_man_print(man, "     an audit log containing all request data (path and query/body data).\n");
  qs_man_print(man, "     Example: 'CustomLog audit_log %{qos-path}n%{qos-query}n'.\n");
  qs_man_print(man, "     See also http://mod-qos.sourceforge.net#qsfiltersample about\n");
  qs_man_print(man, "     the module settings.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -c <path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     mod_qos configuration file defining QS_DenyRequestLine and\n");
  qs_man_print(man, "     QS_PermitUri directives.\n");
  qs_man_print(man, "     %s generates rules from access log data automatically.\n", cmd);
  qs_man_print(man, "     Manually generated rules (QS_PermitUri) may be provided from\n");
  qs_man_print(man, "     this file. Note: each manual rule must be represented by a\n");
  qs_man_print(man, "     request URI in the input data (-i) in order to make sure not\n");
  qs_man_print(man, "     to be deleted by the rule optimisation algorithm.\n");
  qs_man_print(man, "     QS_Deny* rules from this file are used to filter request lines\n");
  qs_man_print(man, "     which should not be used for whitelist rule generation.\n");
  printf("\n");
  printf("     Example:\n");
  qs_man_println(man, "       # manually defined whitelist rule:\n");
  qs_man_println(man, "       QS_PermitUri +view deny \"^[/a-zA-Z0-9]+/view\\?(page=[0-9]+)?$\"\n");
  qs_man_println(man, "       # filter unwanted request line patterns:\n");
  qs_man_println(man, "       QS_DenyRequestLine +printable deny \".*[\\x00-\\x19].*\"\n");
  printf("\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -d <num>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Depth (sub locations) of the path string which is defined as a\n");
  qs_man_print(man, "     literal string. Default is 1.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -h\n");
  if(man) printf("\n");
  qs_man_print(man, "     Always use a string representing the handler name in the path even\n");
  qs_man_print(man, "     the url does not have a query. See also -d option.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -b <num>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Replaces url pattern by the regular expression when detecting\n");
  qs_man_print(man, "     a base64/hex encoded string. Detecting sensibility is defined by a\n");
  qs_man_print(man, "     numeric value. You should use values higher than 5 (default)\n");
  qs_man_print(man, "     or 0 to disable this function.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -p\n");
  if(man) printf("\n");
  qs_man_print(man, "     Repesents query by pcre only (no literal strings).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -s\n");
  if(man) printf("\n");
  qs_man_print(man, "     Uses one single pcre for the whole query string.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -m\n");
  if(man) printf("\n");
  qs_man_print(man, "     Uses one pcre for multipe query values (recommended mode).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -o\n");
  if(man) printf("\n");
  qs_man_print(man, "     Does not care the order of query parameters.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -l <len>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Outsizes the query length by the defined length ({0,size+len}),\n");
  qs_man_print(man, "     default is %d.\n", m_query_len_pcre);
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -n\n");
  if(man) printf("\n");
  qs_man_print(man, "     Disables redundant rules elimination.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -e\n");
  if(man) printf("\n");
  qs_man_print(man, "     Exit on error.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -u 'uni'\n");
  if(man) printf("\n");
  qs_man_print(man, "     Enables additional decoding methods. Use the same settings as you have\n");
  qs_man_print(man, "     used for the QS_Decoding directive.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -k <prefix>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Prefix used to generate rule identifiers (QSF by default).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -t\n");
  if(man) printf("\n");
  qs_man_print(man, "     Calculates the maximal latency per request (worst case) using the\n");
  qs_man_print(man, "     generated rules.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -f <path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Filters the input by the provided path (prefix) only processing\n");
  qs_man_print(man, "     matching lines.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -v <level>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Verbose mode. (0=silent, 1=rule source, 2=detailed). Default is 1.\n");
  qs_man_print(man, "     Don't use rules you haven't checked the request data used to\n");
  qs_man_print(man, "     generate it! Level 1 is highly recommended (as long as you don't\n");
  qs_man_print(man, "     have created the log data using your own web crawler).\n");
  printf("\n");
  if(man) {
    printf(".SH OUTPUT\n");
  } else {
    printf("Output\n");
  }
  qs_man_print(man, " The output of %s is written to stdout. The output\n", cmd);
  qs_man_print(man, " contains the generated QS_PermitUri directives but also\n");
  qs_man_print(man, " information about the source which has been used to generate\n");
  qs_man_print(man, " these rules. It is very important to check the validity of\n");
  qs_man_print(man, " each request line which has been used to calculate the\n");
  qs_man_print(man, " QS_PermitUri rules. Each request line which has been used to\n");
  qs_man_print(man, " generate a new rule is shown in the output prefixed by\n");
  qs_man_print(man, " \"ADD line <line number>:\". These request lines should be\n");
  qs_man_print(man, " stored and reused at any later rule generation (add them to\n");
  qs_man_print(man, " the URI input file). The subsequent line shows the generated\n");
  qs_man_print(man, " rule.\n");
  qs_man_print(man, " At the end of data processing a list of all generated\n");
  qs_man_print(man, " QS_PermitUri rules is shown. These directives may be used\n");
  qs_man_print(man, " withn the configuration file used by mod_qos.\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
  } else {
    printf("Sample Usage and Output\n");
  }
  qs_man_println(man, "  %s -i loc.txt -c httpd.conf -m -e\n", cmd);
  qs_man_println(man, "  ...\n");
  qs_man_println(man, "  # ADD line 1: /aaa/index.do\n");
  qs_man_println(man, "  # 003 ^(/[a-zA-Z0-9\\-_]+)+[/]?\\.?[a-zA-Z]{0,4}$\n");
  qs_man_println(man, "  # ADD line 3: /aaa/view?page=1\n");
  qs_man_println(man, "  # --- ^[/a-zA-Z0-9]+/view\\?(page=[0-9]+)?$\n");
  qs_man_println(man, "  # ADD line 4: /aaa/edit?document=1\n");
  qs_man_println(man, "  # 004 ^[/a-zA-Z]+/edit\\?((document)(=[0-9]*)*[&]?)*$\n");
  qs_man_println(man, "  # ADD line 5: /aaa/edit?image=1.jpg\n");
  qs_man_println(man, "  # 005 ^[/a-zA-Z]+/edit\\?((image)(=[0-9\\.a-zA-Z]*)*[&]?)*$\n");
  qs_man_println(man, "  ...\n");
  qs_man_println(man, "  QS_PermitUri +QSF001 deny \"^[/a-zA-Z]+/edit\\?((document|image)(=[0-9\\.a-zA-Z]*)*[&]?)*$\"\n");
  qs_man_println(man, "  QS_PermitUri +QSF002 deny \"^[/a-zA-Z0-9]+/view\\?(page=[0-9]+)?$\"\n");
  qs_man_println(man, "  QS_PermitUri +QSF003 deny \"^(/[a-zA-Z0-9\\-_]+)+[/]?\\.?[a-zA-Z]{0,4}$\"\n");
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsgeo(1), qsgrep(1), qshead(1), qslog(1), qslogger(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://mod-qos.sourceforge.net/\n");
  } else {
    printf("mod_qos %s\n", man_version);
    printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  }
  if(man) {
    exit(0);
  } else {
    exit(1);
  }
}

/* worker struct, used for parallel processing */
typedef struct {
  apr_pool_t *pool;
  apr_table_t *rules;
  apr_table_t *rules_url;
  int from;
  int to;
} qs_worker_t;

/* determines, if a rule is really required */
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

/* get the characters used withn the string in order to define a pcre */
static char *qos_2pcre(apr_pool_t *pool, const char *line) {
  int hasA = 0;
  int hasD = 0;
  int hasE = 0;
  int hasB = 0;
  int i = 0;
  unsigned char *in = (unsigned char *)line;
  char *ret = apr_pcalloc(pool, strlen(line) * 6);
  int reti = 0;
  char *existing = "";
  if(strlen(line) == 0) return "";
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
    } else if(in[i] == '\0') {
      char *ck = apr_psprintf(pool, "#\\x%02x#", in[i]);
      if(strstr(existing, ck) == NULL) {
        sprintf(&ret[reti], "\\x%02x", in[i]);
        reti = reti + 4;
        existing = apr_pstrcat(pool, existing, ck, NULL);
      }
    } else if(strchr(ret, in[i]) == NULL) {
      if(strchr(QS_PCRE_RESERVED, in[i]) != NULL) {
        ret[reti] = '\\';
        reti++;
        ret[reti] = in[i];
        reti++;
      } else if((in[i] < ' ') || (in[i]  > '~')) {
        char *ck = apr_psprintf(pool, "#\\x%02x#", in[i]);
        if(strstr(existing, ck) == NULL) {
          sprintf(&ret[reti], "\\x%02x", in[i]);
          reti = reti + 4;
          existing = apr_pstrcat(pool, existing, ck, NULL);
        }
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

/* check for the pattern "p" in "r" using the delimter "d",
   returns 1 if it is in the string */
static int qos_checkstr(apr_pool_t *pool, char *r, char *d, char *p) {
  /*
   * r = ..|p|..
   * r = p|...
   * r = ..|p
   * r = p
   */
  char *check1 = apr_pstrcat(pool, d, p, d, NULL);
  char *check2 = apr_pstrcat(pool, p, d, NULL);
  char *check3 = apr_pstrcat(pool, d, p, NULL);

  if(strstr(r, check1) != NULL) {
    return 1;
  }
  if(strncmp(r, check2, strlen(check2)) == 0) {
    return 1;
  }
  if(strlen(r) > strlen(check3)) {
    if((strncmp(&r[strlen(r)-strlen(check3)], check3, strlen(check3)) == 0)) {
      return 1;
    }
  }
  if(strcmp(r, p) == 0) {
    return 1;
  }

  return 0;
}

/* add the string "n" to "o" using the delimiter "d" (only if not
   already available */
static char *qos_addstr(apr_pool_t *pool, char *o, char *d, char *n) {
  char *p = apr_pstrdup(pool, n);
  char *r = o;
  if(n == NULL) return o;
  while(p && p[0]) {
    char *this = p;
    char *next = strchr(p, d[0]);

    /* \| */
    while(next) {
      if((next > this) && (next[-1] == '\\')) {
        next++;
        next = strchr(next, d[0]);
      } else {
        break;
      }
    }
    if(next == NULL) {
      p = NULL;
    } else {
      next[0] = '\0';
      next++;
      p = next;
    }
    if(!qos_checkstr(pool, r, d, this)) {
      r = apr_pstrcat(pool, r, d, this, NULL);
    }
  }
  return r;
}


/* create a name=pcre string like this: ((s1|s2)(=[<pcre>]*)*[&]?)*" */
static char *qos_qqs(apr_pool_t *pool, char *string, char *query_pcre, int singleEq, int hasEq, int startAmp) {
  char *se = NULL;
  char *s = "";
  if(startAmp) s = "[&]?";
  if(singleEq) {
    se = "(=[&]?)*";
  }
  if(strlen(query_pcre) > 0) {
    return apr_pstrcat(pool, s, "((", string, ")(=[", qos_2pcre(pool, query_pcre), "]*)*[&]?)*", se, NULL);
  } else {
    if(hasEq && !singleEq) {
      se = "(=[&]?)*";
      return apr_pstrcat(pool, s, "(((", string, ")[&]?)*", se, ")*", NULL);
    }
    return apr_pstrcat(pool, s, "((", string, ")[&]?)*", se, NULL);
  }
}

/* tries to optimize the rules by merging all query into one single pcre matching
   all values */
static void qos_query_optimization(apr_pool_t *pool, apr_table_t *rules) {
  apr_table_t *delete = apr_table_make(pool, 1);
  apr_table_t *checked_path = apr_table_make(pool, 1);
  apr_table_t *new = apr_table_make(pool, 1);
  int i, j;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    char *rule_str = entry[i].key;
    qs_rule_t *r = (qs_rule_t *)entry[i].val;
    if(!r->fragment && r->path && (apr_table_get(checked_path, r->path) == NULL)) {
      int merged = 0;
      char *query_m_string = r->query_m_string == NULL ? "" : r->query_m_string;
      char *query_m_pcre = r->query_m_pcre == NULL ? "" : r->query_m_pcre;
      if(m_verbose > 1) printf("  search for path %s (%s)\n", r->path, rule_str);
      if(m_verbose > 1) printf("  . %s %s\n", query_m_string, query_m_pcre);
      apr_table_add(checked_path, r->path, "");
      /* search for rules with the same path and delete them */
      for(j = 0; j < apr_table_elts(rules)->nelts; j++) {
        if(i != j) {
          qs_rule_t *n = (qs_rule_t *)entry[j].val;
          if(!n->fragment && n->path && (strcmp(r->path, n->path) == 0)) {
            if(m_verbose > 1) printf("  + %s %s\n",
                                     n->query_m_string == NULL ? "-" : n->query_m_string,
                                     n->query_m_pcre == NULL ? "-" : n->query_m_pcre);
            if(strlen(query_m_string) == 0) {
              query_m_string = apr_pstrcat(pool, query_m_string, n->query_m_string, NULL);
            } else {
              query_m_string = qos_addstr(pool, query_m_string, "|", n->query_m_string);
            }
            if(m_verbose > 1) printf("  > %s\n", query_m_string);
            query_m_pcre = apr_pstrcat(pool, query_m_pcre, n->query_m_pcre, NULL);
            apr_table_add(delete, entry[j].key, "");
            merged = 1;
          }
        }
      }
      /* update rule if merged to any */
      if(merged) {
        apr_table_add(delete, entry[i].key, "");
        if(m_verbose) {
          printf("# CHANGE: <%s>", rule_str);
        }
        {
          const char *errptr = NULL;
          char *rule = apr_pstrcat(pool, "^", r->path, NULL);
          qs_rule_t *rs = apr_pcalloc(pool, sizeof(qs_rule_t));
          if(strlen(query_m_string) > 0) {
            rule = apr_pstrcat(pool, rule, "\\?",
                               qos_qqs(pool, query_m_string, query_m_pcre, 0, 0, 0), NULL);
          }
          rule = apr_pstrcat(pool, rule, "$", NULL);
          rs->pcre = qos_pcre_compile(rule, 0);
          rs->extra = pcre_study(rs->pcre, 0, &errptr);
          rs->path = r->path;
          apr_table_setn(new, rule, (char *)rs);
          if(m_verbose) {
            printf(" to <%s>\n", rule);
            fflush(stdout);
          }
        }
      }
    }
  }
  entry = (apr_table_entry_t *)apr_table_elts(delete)->elts;
  for(i = 0; i < apr_table_elts(delete)->nelts; i++) {
    if(m_verbose) printf("# DEL rule: %s\n", entry[i].key);
    apr_table_unset(rules, entry[i].key);
  }
  entry = (apr_table_entry_t *)apr_table_elts(new)->elts;
  for(i = 0; i < apr_table_elts(new)->nelts; i++) {
    apr_table_setn(rules, entry[i].key, entry[i].val);
  }
}

/* deletes rules which are not required and merge query name/value pairs */
static void qos_delete_obsolete_rules(apr_pool_t *pool, apr_table_t *rules, apr_table_t *rules_url) {
  apr_table_t *not_used = apr_table_make(pool, 1);
  apr_table_t *used;
  apr_table_t *used1;
  pthread_attr_t *tha = NULL;
  pthread_t tid;
  qs_worker_t *wt = apr_pcalloc(pool, sizeof(qs_worker_t));


  if(m_query_multi_pcre) {
    if(m_verbose) {
      printf("# search for redundant rules ...\n");
      fflush(stdout);
    }
    qos_query_optimization(pool, rules);
    if(m_verbose) printf("# ");
  } else {
    if(m_verbose) {
      printf("# search for redundant rules ");
      fflush(stdout);
    }
  }

  wt->pool = pool;
  wt->rules = rules;
  wt->rules_url = rules_url;
  wt->from = apr_table_elts(rules)->nelts / 2;
  wt->to = apr_table_elts(rules)->nelts;

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

/* test if we need to create a new url (and save line if the rule is used the very
   first time (rule has been read from the configuration file)) */
static int qos_test_for_existing_rule(char *plain, char *line, apr_table_t *rules, 
                                      apr_table_t *special_rules, int line_nr,
                                      apr_table_t *rules_url, apr_table_t *source_rules, int first) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  if((line == 0) || (strlen(line) == 0)) return 0;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    qs_rule_t *rs = (qs_rule_t *)entry[i].val;
    if(pcre_exec(rs->pcre, rs->extra, line, strlen(line), 0, 0, NULL, 0) >= 0) {
      if(first && (apr_table_get(source_rules, entry[i].key) == NULL)) {
        apr_table_add(source_rules, entry[i].key, "");
        apr_table_add(rules_url, line, "");
        apr_table_setn(special_rules, entry[i].key, (char *)rs);
        if(m_verbose) {
          printf("# ADD line %d: %s\n", line_nr, plain);
          printf("# --- %s\n", entry[i].key);
        }
      }
      if(m_verbose > 1){
        printf("LINE %d, exiting rule: %s\n", line_nr, entry[i].key);
      }
      return 1;
    }
  }
  /* check for special rules */
  entry = (apr_table_entry_t *)apr_table_elts(special_rules)->elts;
  for(i = 0; i < apr_table_elts(special_rules)->nelts; i++) {
    qs_rule_t *rs = (qs_rule_t *)entry[i].val;
    if(pcre_exec(rs->pcre, rs->extra, line, strlen(line), 0, 0, NULL, 0) >= 0) {
      if(m_verbose) {
        printf("# ADD line %d: %s\n", line_nr, plain);
        printf("# -(S) %s\n", entry[i].key);
      }
      apr_table_setn(rules, entry[i].key, (char *)rs);
      return 1;
    }
  }
  return 0;
}

/* filter lines we don't want to add to the whitelist */
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

/* load existing rules */
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
              if(p[0] == '"') {
                int fl = strlen(p)-2;
                pattern = apr_psprintf(pool, "%.*s", fl, &p[1]);
              } else {
                int fl = strlen(p);
                pattern = apr_psprintf(pool, "%.*s", fl, p);
              }
              pcre_test = qos_pcre_compile(pattern, option);
              extra = pcre_study(pcre_test, 0, &errptr);
              rs = apr_pcalloc(pool, sizeof(qs_rule_t));
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

/* tries to map a base64 string to a pcre */
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


/* maps a query string to a pairs of <string>=<pcre> or <pcre>=<pcre> */
static char *qos_query_string_pcre(apr_pool_t *pool, const char *path) {
  char *copy = apr_pstrdup(pool, path);
  char *pos = copy;
  char *ret = "";
  int isValue = 0;
  int open = 0;
  while(copy[0]) {
    if((copy[0] == '=') && (copy[1] != '=') && !open) {
      copy[0] = '\0';
      qos_unescaping(pos);
      if(!open) {
        ret = apr_pstrcat(pool, ret, "(", NULL);
        open = 1;
      }
      if(m_query_pcre) {
        if(strlen(pos) > 0) {
          ret = apr_pstrcat(pool, ret, "[", qos_2pcre(pool, pos), "]+=", NULL);
        } else {
          ret = apr_pstrcat(pool, ret, "=", NULL);
        }
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
        ret = apr_psprintf(pool, "%s[%s]{0,%"APR_SIZE_T_FMT"}[&]?", ret, qos_2pcre(pool, pos),
                           strlen(pos) + m_query_len_pcre);
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
      ret = apr_psprintf(pool, "%s[%s]{0,%"APR_SIZE_T_FMT"}[&]?", ret, qos_2pcre(pool, pos),
                         strlen(pos) + m_query_len_pcre);
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
  if(m_query_pcre) {
    return ret;
  } else {
    return ret;
    /* it woud be nice to use (see -o):
     *  ((a=b)?(c=d)?)* 
     * instead of:
     *  (a=b)?(c=d)? and (c=d)?(a=b)?
     * but in this case, two rules are much faster than one
     * it's probably better to use the -m option
     */
  }
}

/* maps a query string to a list of names and a single pcre for all values:
   <string>|<string>=<pcre> */
static char *qos_multi_query_string_pcre(apr_pool_t *pool, const char *path,
                                         char **query_m_string, char **query_m_pcre) {
  char *copy = apr_pstrdup(pool, path);
  char *pos = copy;
  char *string = "";
  char *query_pcre = "";
  int isValue = 0;
  int singleEq = 0;
  int hasEq = 0;
  int startAmp = 0;
  if(copy[0] == '&') startAmp = 1;
  while(copy[0]) {
    if(copy[0] == '=') hasEq = 1;
    if((copy[0] == '=') && (copy[1] != '=') && !isValue) {
      copy[0] = '\0';
      qos_unescaping(pos);
      if(strlen(pos) > 0) {
        if(strlen(string) > 0) string = apr_pstrcat(pool, string, "|",  NULL);
        string = apr_pstrcat(pool, string, qos_escape_pcre(pool, pos),  NULL);
      } else {
        if((copy[1] == '&') || (copy[1] == '\0')) {
          singleEq = 1;
        }
      }
      pos = copy;
      pos++;
      isValue = 1;
    }
    if(copy[0] == '&') {
      copy[0] = '\0';
      if(!isValue) {
        qos_unescaping(pos);
        if(strlen(string) > 0) string = apr_pstrcat(pool, string, "|",  NULL);
        string = apr_pstrcat(pool, string, qos_escape_pcre(pool, pos),  NULL);
      } else {
        if(strlen(pos) != 0) {
          qos_unescaping(pos);
          query_pcre = apr_pstrcat(pool, query_pcre, pos,  NULL);
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
      query_pcre = apr_pstrcat(pool, query_pcre, pos, NULL);
    } else {
      if(strlen(string) > 0) string = apr_pstrcat(pool, string, "|",  NULL);
      string = apr_pstrcat(pool, string, qos_escape_pcre(pool, pos),  NULL);
    }
  }
  *query_m_string = string;
  *query_m_pcre = query_pcre;
  return qos_qqs(pool, string, query_pcre, singleEq, hasEq, startAmp);
}

/* maps a path to a single pcre (don't mind its length) */
static char *qos_path_pcre(apr_pool_t *lpool, const char *path) {
  char *dec = apr_pstrdup(lpool, path);
  qos_unescaping(dec);
  return apr_pstrcat(lpool, "[", qos_2pcre(lpool, dec), "]+", NULL);
}

/* maps a path to <pcre>/<string> */
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
    qos_unescaping(last);
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
    if(nohandler) {
      rx = apr_pstrcat(lpool, rx, str, "[/]?", NULL);
    } else {
      rx = apr_pstrcat(lpool, rx, str, NULL);
    }
  }
  return rx;
}

static int qos_is_alnum(const char *string) {
  unsigned char *in = (unsigned char *)string;
  int i = 0;
  if(in == NULL) return 0;
  while(in[i]) {
    if(!apr_isalnum(in[i])) return 0;
    i++;
  }
  return 1;
}

static void qos_rule_optimization(apr_pool_t *pool, apr_pool_t *lpool,
                                  apr_table_t *rules, apr_table_t *special_rules) {
  int i;
  apr_table_t *new_rules = apr_table_make(pool, 5);
  apr_table_t *del_rules = apr_table_make(pool, 5);
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
  for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
    qs_rule_t *rs = (qs_rule_t *)entry[i].val;
    int hit = 0;
    int j;
    for(j = 0; j < apr_table_elts(rules)->nelts; j++) {
      if(i != j) {
        qs_rule_t *rsj = (qs_rule_t *)entry[j].val;
        if(rs->query_m_string && rsj->query_m_string) {
          if(strcmp(rs->query_m_string, rsj->query_m_string) == 0) {
            if(strlen(entry[i].key) == strlen(entry[j].key)) {
              hit++;
            }
          }
          if(hit == 5) {
            int s = 0;
            int e = 0;
            while(entry[i].key[s] && (entry[i].key[s] == entry[j].key[s])) s++;
            e = s;
            while(entry[i].key[e] &&
                  ((entry[i].key[e] != entry[j].key[e]) ||
                   (apr_isalnum(entry[i].key[e]) && apr_isalnum(entry[j].key[e])))) e++;
            if((e > s) &&
               (s > 14) &&
               (e < strlen(entry[i].key)) &&
               (strstr(&entry[i].key[e], "\?") != NULL)) {
              const char *errptr = NULL;
              char *match = apr_psprintf(lpool, "%.*s%.*s",
                                         e-s, &entry[i].key[s],
                                         e-s, &entry[j].key[s]);
              if(qos_is_alnum(match)) {
                char *matchx = apr_psprintf(lpool, "[%s]{%d}", qos_2pcre(lpool, match), e-s);
                char *new = apr_psprintf(pool, "%.*s%s%s", s, entry[i].key, matchx, &entry[i].key[e]);
                qs_rule_t *rsn = apr_pcalloc(pool, sizeof(qs_rule_t));
                rsn->pcre = qos_pcre_compile(new, 0);
                rsn->extra = pcre_study(rsn->pcre, 0, &errptr);
                rsn->path = rs->path;
                rsn->query_m_string = rs->query_m_string;
                rsn->query_m_pcre = rs->query_m_pcre;
                rsn->fragment = rs->fragment;
                if(m_verbose) {
                  printf("# CHANGE: <%s> to <%s>\n", entry[i].key, new);
                  fflush(stdout);
                }
                apr_table_setn(new_rules, new, (char *)rsn);
                apr_table_addn(del_rules, entry[i].key, entry[i].val);
                apr_table_addn(del_rules, entry[j].key, entry[j].val);
                if(m_verbose > 1) {
                  if(m_verbose) printf("  [%s] [%s]\n", entry[i].key, entry[j].key);
                  if(m_verbose) printf("  [%s] [%s]\n", match, matchx);
                }
                break;
              }
            }
          }
        }
      }
    }
  }
  entry = (apr_table_entry_t *)apr_table_elts(new_rules)->elts;
  for(i = 0; i < apr_table_elts(new_rules)->nelts; i++) {
    apr_table_setn(rules, entry[i].key, entry[i].val);
  }
  entry = (apr_table_entry_t *)apr_table_elts(del_rules)->elts;
  for(i = 0; i < apr_table_elts(del_rules)->nelts; i++) {
    apr_table_unset(rules, entry[i].key);
  }
}

/* rules do not care the order of parameter values (makes rule processing slow)
 *  (id=[0-9]{0,13}[&]?)?(name=[a-zA-Z]{0,12}[&]?)?
 * ((id=[0-9]{0,13}[&]?)|(name=[a-zA-Z]{0,12}[&]?))*
 */
static char *qos_post_optimization(apr_pool_t *lpool, char *query) {
  int hit = 0;
  char *p = query;
  while(p && p[0]) {
    if(strncmp(p, "[&]?)?(", 7) == 0) {
      hit = 1;
      p[5] = '|';
    }
    p++;
  }
  if(hit) {
    query[strlen(query)-1] = '\0';
    return apr_psprintf(lpool, "(%s)*", query);
  }
  return query;
}

static void qos_auto_detect(char **raw) {
  char *line = *raw;
  int rc_c = -1;
  if(m_req_regex) {
    int ovector[QS_OVECCOUNT];
    /* no request line, maybe raw Apache access log? */
    rc_c = pcre_exec(m_req_regex, NULL, line, strlen(line), 0, 0, ovector, QS_OVECCOUNT);
    if(rc_c >= 0) {
      char *sr;
      line = &line[ovector[0]];
      line[ovector[1] - ovector[0]] = '\0';
      sr = strchr(line, ' ');
      while(sr[0] == ' ')sr++;
      *raw = sr;
      sr = strrchr(line, ' ');
      sr[0] = '\0';
    }
  }
  if(rc_c < 0) {
    /* or an audit log like "%h %>s %{qos-loc}n %{qos-path}n%{qos-query}n" */
    char *pe = line;
    int pi = 3;
    while(pe && (pi > 0)) {
      pi--;
      pe = strchr(pe, ' ');
      if(pe) {
        pe++;
      }
    }
    if(pe && pe[0] == '/' && (pi == 0)) {
      *raw = pe;
    }
  }
  return;
}

/* process the input file line by line */
static void qos_process_log(apr_pool_t *pool, apr_table_t *blacklist, apr_table_t *rules,
                            apr_table_t *rules_url, apr_table_t *special_rules,
                            FILE *f, int *ln, int *dc, int first) {
  char *readline = apr_pcalloc(pool, MAX_BODY_BUFFER);
  int deny_count = *dc;
  int line_nr = *ln;
  apr_table_t *source_rules = apr_table_make(pool, 10);
  int rule_optimization = 300;
  while(!qos_fgetline(readline, MAX_BODY_BUFFER, f)) {
    int doubleSlash = 0;
    apr_uri_t parsed_uri;
    apr_pool_t *lpool;
    char *line = readline;
    apr_pool_create(&lpool, NULL);
    line_nr++;
    if((strlen(line) > 1) && line[1] == '/') {
      doubleSlash = 1;
      line++;
    }
    if(line[0] != '/') {
      if(!m_log_req_regex) {
        m_log_req_regex = 1;
        fprintf(stderr, "WARNING, line %d: "
                "unexpected data format, try to detect request lines automatically\n",
                line_nr);
      }
      qos_auto_detect(&line);
    }
    if(apr_uri_parse(lpool, line, &parsed_uri) != APR_SUCCESS) {
      fprintf(stderr, "ERROR, could parse uri %s\n", line);
      if(m_exit_on_error) exit(1);
    }
    if(parsed_uri.path == NULL || (parsed_uri.path[0] != '/')) {
      fprintf(stderr, "WARNING, line %d: invalid request %s\n", line_nr, line);
    } else if(m_filter && parsed_uri.path && strncmp(parsed_uri.path, m_filter, strlen(m_filter)) != 0) {
      // skip filtered line
    } else {
      char *path = NULL;
      char *query = NULL;
      char *query_m_string = NULL;
      char *query_m_pcre = NULL;
      char *fragment = NULL;
      char *copy = apr_pstrdup(lpool, line);
      qos_unescaping(copy);
      if(qos_enforce_blacklist(blacklist, copy)) {
        fprintf(stderr, "WARNING: blacklist filter match at line %d for %s\n",
                line_nr, line);
        deny_count++;
      } else {
        if(!qos_test_for_existing_rule(line, copy, rules, special_rules,
                                       line_nr, rules_url, source_rules, first)) {
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
              if(!m_query_multi_pcre) {
                query = qos_query_string_pcre(lpool, parsed_uri.query);
                if(m_query_o_pcre) {
                  query = qos_post_optimization(lpool, query);
                }
              } else {
                query = qos_multi_query_string_pcre(lpool, parsed_uri.query,
                                                    &query_m_string, &query_m_pcre);
              }
            }
          } else {
            if(strcmp(parsed_uri.path, "/") == 0) {
              path = apr_pstrdup(lpool, "/");
            } else {
              if(m_handler) {
                path = qos_path_pcre_string(lpool, parsed_uri.path);
              } else {
                if(pcre_exec(pcre_simple_path, NULL, parsed_uri.path,
                             strlen(parsed_uri.path), 0, 0, NULL, 0) >= 0) {
                  path = apr_pstrdup(lpool, QS_SIMPLE_PATH_PCRE);
                } else {
                  path = qos_path_pcre(lpool, parsed_uri.path);
                }
              }
            }
          }
          if(parsed_uri.fragment) {
            char *f = apr_pstrdup(lpool, parsed_uri.fragment);
            if(strlen(f) > 0) {
              qos_unescaping(f);
              fragment = apr_pstrcat(lpool, "[", qos_2pcre(lpool, f), "]+", NULL);
            } else {
              fragment = apr_pstrcat(lpool, "", NULL);
            }
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
            char *rule;
            qs_rule_t *rs = apr_pcalloc(pool, sizeof(qs_rule_t));
            if(doubleSlash) {
              rule = apr_pstrcat(pool, "^[/]?", path, NULL);
            } else {
              rule = apr_pstrcat(pool, "^", path, NULL);
            }
            if(query) {
              rule = apr_pstrcat(pool, rule, "\\?", query, NULL);
            }
            if(fragment) {
              rule = apr_pstrcat(pool, rule, "#", fragment, NULL);
              rs->fragment = 1;
            } else {
              rs->fragment = 0;
            }
            rule = apr_pstrcat(pool, rule, "$", NULL);
            rs->pcre = qos_pcre_compile(rule, 0);
            rs->extra = pcre_study(rs->pcre, 0, &errptr);
            rs->path = apr_pstrdup(pool, path);
            if(m_query_multi_pcre && !fragment) {
              rs->query_m_string = apr_pstrdup(pool, query_m_string);
              rs->query_m_pcre = apr_pstrdup(pool, query_m_pcre);
            } else {
              rs->query_m_string = NULL;
              rs->query_m_pcre = NULL;
            }
            // don't mind if extra is null
            if(m_verbose) {
              printf("# ADD line %d: %s\n", line_nr, line);
              printf("# %.3d %s\n", apr_table_elts(rules)->nelts+1, rule);
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
              apr_table_add(source_rules, rule, "");
              apr_table_setn(rules, rule, (char *)rs);
            }
            if(apr_table_elts(rules)->nelts == 2000) {
              fprintf(stderr, "ERROR, too many rules (limited to max. 2000)\n");
              if(m_exit_on_error) exit(1);
            }
            /* rule optimazion searching for redundant patterns (only in
	       conjunction with -m, -b and !-n */
            if((apr_table_elts(rules)->nelts == rule_optimization) &&
               m_redundant &&
               m_query_multi_pcre &&
               m_base64) {
              /* got too many rules, try to find more general rules */
              if(m_verbose) {
                printf("# too many rules: start rule optimization ...\n");
                fflush(stdout);
              }
              qos_rule_optimization(pool, lpool, rules, special_rules);
              if(m_verbose) {
                printf("# continue with rule generation\n");
                fflush(stdout);
              }
              rule_optimization = rule_optimization + 200;
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

static void qos_measurement(apr_pool_t *pool, apr_table_t *blacklist, apr_table_t *rules, FILE *f, int *ln) {
  char *readline = apr_pcalloc(pool, MAX_BODY_BUFFER);
  int line_nr = 0;
  while(!qos_fgetline(readline, MAX_BODY_BUFFER, f)) {
    apr_uri_t parsed_uri;
    apr_pool_t *lpool;
    char *line = readline;
    apr_pool_create(&lpool, NULL);
    line_nr++;
    if((strlen(line) > 1) && line[1] == '/') {
      strcpy(line, &line[1]);
    }
    if(line[0] != '/') {
      qos_auto_detect(&line);
    }
    if(apr_uri_parse(lpool, line, &parsed_uri) != APR_SUCCESS) {
      fprintf(stderr, "ERROR, could parse uri %s\n", line);
      if(m_exit_on_error) exit(1);
    }
    if(parsed_uri.path == NULL || (parsed_uri.path[0] != '/')) {
      fprintf(stderr, "WARNING, line %d: invalid request %s\n", line_nr, line);
    } else {
      char *copy = apr_pstrdup(lpool, line);
      int i;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
      qos_unescaping(copy);
      for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
        qs_rule_t *rs = (qs_rule_t *)entry[i].val;
        pcre_exec(rs->pcre, NULL, copy, strlen(copy), 0, 0, NULL, 0);
      }
    }
    apr_pool_destroy(lpool);
  }
  *ln = line_nr;
}

int main(int argc, const char * const argv[]) {
  apr_table_entry_t *entry;
  long performance = -1;
  time_t start = time(NULL);
  time_t end;
  int line_nr = 0;
  int deny_count = 0;
  char *time_string;
  int i, rc;
  const char *access_log = NULL;
  FILE *f;
  apr_pool_t *pool;
  apr_table_t *rules;
  apr_table_t *special_rules;
  apr_table_t *blacklist;
  apr_table_t *rules_url;
  int blacklist_size = 0;
  int whitelist_size = 0;
  char *cmd = strrchr(argv[0], '/');
  const char *httpdconf = NULL;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  rules = apr_table_make(pool, 10);
  special_rules = apr_table_make(pool, 10);
  blacklist = apr_table_make(pool, 10);
  rules_url = apr_table_make(pool, 10);
  rc = nice(10);
  if(rc == -1) {
    fprintf(stderr, "ERROR, failed to change nice value: %s\n", strerror(errno));
  }
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
    } else if(strcmp(*argv,"-k") == 0) {
      if (--argc >= 1) {
        m_pfx = *(++argv);
      }
    } else if(strcmp(*argv,"-f") == 0) {
      if (--argc >= 1) {
        m_filter = *(++argv);
      }
    } else if(strcmp(*argv,"-d") == 0) {
      if (--argc >= 1) {
        m_path_depth = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-u") == 0) {
      if (--argc >= 1) {
        const char *coders = *(++argv);
        if(strstr(coders, "uni")) {
          m_mode |= QOS_DEC_MODE_FLAGS_UNI;
        }
        if(strstr(coders, "ansi")) {
          m_mode |= QOS_DEC_MODE_FLAGS_ANSI;
        }
        if(strstr(coders, "html")) {
          m_mode |= QOS_DEC_MODE_FLAGS_HTML;
        }
      }
    } else if(strcmp(*argv,"-n") == 0) {
      m_redundant = 0;
    } else if(strcmp(*argv,"-b") == 0) {
      if (--argc >= 1) {
        m_base64 = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-l") == 0) {
      if (--argc >= 1) {
        m_query_len_pcre = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-p") == 0) {
      m_query_pcre = 1;
    } else if(strcmp(*argv,"-m") == 0) {
      m_query_multi_pcre = 1;
    } else if(strcmp(*argv,"-o") == 0) {
      m_query_o_pcre = 1;
    } else if(strcmp(*argv,"-s") == 0) {
      m_query_single_pcre = 1;
    } else if(strcmp(*argv,"-e") == 0) {
      m_exit_on_error = 1;
    } else if(strcmp(*argv,"-t") == 0) {
      performance = 0;
    } else if(strcmp(*argv,"-h") == 0) {
      m_handler = 1;
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    }
    argc--;
    argv++;
  }
  qos_init_pcre();

  if((m_query_pcre && m_query_multi_pcre) ||
     (m_query_pcre && m_query_single_pcre) ||
     (m_query_multi_pcre && m_query_single_pcre) ||
     (m_query_pcre && m_query_o_pcre) ||
     (m_query_multi_pcre && m_query_o_pcre) ||
     (m_query_single_pcre && m_query_o_pcre)) {
    fprintf(stderr, "ERROR, option -s,-m,-o or -p can't be used together.\n");
    exit(1);
  }

  if(httpdconf) {
    qos_load_blacklist(pool, blacklist, httpdconf);
    blacklist_size = apr_table_elts(blacklist)->nelts;
    qos_load_whitelist(pool, rules, httpdconf);
    whitelist_size = apr_table_elts(rules)->nelts;
  }

  if(access_log == NULL) usage(cmd, 0);
  f = fopen(access_log, "r");
  if(f == NULL) {
    fprintf(stderr, "ERROR, could not open input file %s\n", access_log);
    exit(1);
  }
  qos_process_log(pool, blacklist, rules, rules_url, special_rules, f, &line_nr, &deny_count, 1);
  fclose(f);

  if(m_redundant) {
    int xl = 0;
    int y = 0;
    // delete useless rules
    qos_delete_obsolete_rules(pool, rules, rules_url);
    // ensure, we have not deleted to many!
    if(m_verbose) {
      printf("# verify new rules ...\n"); 
      fflush(stdout);
    }
    //    if(httpdconf) {
    //      qos_load_whitelist(pool, rules, httpdconf);
    //    }
    f = fopen(access_log, "r");
    qos_process_log(pool, blacklist, rules, rules_url, special_rules, f, &xl, &y, 0);
    fclose(f);
  }

  if(performance == 0) {
    int lx = 0;
    apr_time_t tv;
    f = fopen(access_log, "r");
    tv = apr_time_now();
    qos_measurement(pool, blacklist, rules, f, &lx);
    tv = apr_time_now() - tv;
    performance = apr_time_msec(tv) + (apr_time_sec(tv) * 1000);
    performance = performance / lx;
    fclose(f);
  }

  end = time(NULL);
  time_string = ctime(&end);
  time_string[strlen(time_string) - 1] = '\0';
  printf("\n# --------------------------------------------------------\n");
  printf("# %s\n", time_string);
  printf("# %d rules from %d access log lines\n", apr_table_elts(rules)->nelts, line_nr);
  printf("#  mod_qos version: %s\n", man_version);
  if(performance >= 0) {
    printf("#  performance index (ms/req): %ld\n", performance);
  }
  printf("#  source (-i): %s\n", access_log);
  printf("#  path depth (-d): %d\n", m_path_depth);
  printf("#  disable path only regex (-h): %s\n", m_handler == 1 ? "yes" : "no");
  printf("#  base64 detection level (-b): %d\n", m_base64);
  printf("#  redundancy check (-n): %s\n", m_redundant == 1 ? "yes" : "no");
  printf("#  pcre only for query (-p): %s\n", m_query_pcre == 1 ? "yes" : "no");
  printf("#  decoding (-u): url");
  if(m_mode & QOS_DEC_MODE_FLAGS_UNI) {
    printf(" uni");
  }
  if(m_mode & QOS_DEC_MODE_FLAGS_HTML) {
    printf(" html");
  }
  if(m_mode & QOS_DEC_MODE_FLAGS_ANSI) {
    printf(" ansi");
  }
  printf("\n");
  printf("#  one pcre for query value (-m): %s\n", m_query_multi_pcre == 1 ? "yes" : "no");
  if(m_query_o_pcre) {
    printf("#  ignore query order (-o): yes\n");
  }
  printf("#  single pcre for query (-s): %s\n", m_query_single_pcre == 1 ? "yes" : "no");
  printf("#  query outsize (-l): %d\n", m_query_len_pcre);
  printf("#  exit on error (-e): %s\n", m_exit_on_error == 1 ? "yes" : "no");
  printf("#  rule file (-c): %s\n", httpdconf == NULL ? "-" : httpdconf);
  if(httpdconf) {
    printf("#    whitelist (loaded existing rules): %d\n", whitelist_size);
    printf("#    blacklist (loaded deny rules): %d\n", blacklist_size);
    printf("#    blacklist matches: %d\n", deny_count);
  }
  printf("#  duration: %ld minutes\n", (end - start) / 60);
  printf("# --------------------------------------------------------\n");

  {
    STACK_OF(qs_rule_t) *st = sk_new(STACK_qs_cmp);
    qs_rule_t *r;
    int j = 1;
    entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
    for(i = 0; i < apr_table_elts(rules)->nelts; i++) {
      //  printf("QS_PermitUri +QSF%0.3d deny \"%s\"\n", i+1, entry[i].key);
      r = apr_pcalloc(pool, sizeof(qs_rule_t));
      r->rule = entry[i].key;
      sk_push(st, (char *)r);
    }
    sk_sort(st);
    i = sk_num(st);
    for(; i > 0; i--) {
      r = (qs_rule_t *)sk_value(st, i-1);
      printf("QS_PermitUri +%s%.3d deny \"%s\"\n",
             m_pfx ? m_pfx : "QSF",
             j, qs_apache_escape(pool, r->rule));
      j++;
    }
  }

  apr_pool_destroy(pool);
  return 0;
}
