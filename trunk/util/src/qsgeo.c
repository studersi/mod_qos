/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */
/**
 * Utilities for the quality of service module mod_qos.
 *
 * qsgeo.c: resolves the country codes of IP addresses
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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <regex.h>

/* apr */
#include <pcre.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>
#include <apr_base64.h>

#include "qs_util.h"

#define MAX_REG_MATCH 10

// "3758096128","3758096383","AU"
#define QS_GEO_PATTERN "\"([0-9]+)\",\"([0-9]+)\",\"([A-Z0-9]{2}|-)\""
// "3758096128","3758096383","AU","Australia"
#define QS_GEO_PATTERN_D "\"([0-9]+)\",\"([0-9]+)\",\"([A-Z0-9]{2})\",\"(.*)\""
// "192.83.198.0","192.83.198.255","3226715648","3226715903","AU","Australia"
#define QS_GEO_PATTERN_EXT  "\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\",\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\",\"([0-9]+)\",\"([0-9]+)\",\"([A-Z0-9]{2})\""
// 182.12.34.23
#define IPPATTERN "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})[\"'\x0d\x0a, ]+"
#define IPPATTERN2 "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})[\"'\x0d\x0a,; ]+"

static int m_inject = 0;
static int m_verbose = 0;

typedef struct {
  unsigned long start;
  char *c;
} qos_inj_t;

static const qos_inj_t m_inj[] = {
  { 167772160, "\"10.0.0.0\",\"10.255.255.255\",\"167772160\",\"184549375\",\"PV\",\"private network\"" },
  { 2130706432, "\"127.0.0.0\",\"127.255.255.255\",\"2130706432\",\"2147483647\",\"LO\",\"local loopback\"" },
  { 2886729728, "\"172.16.0.0\",\"172.31.255.255\",\"2886729728\",\"2887778303\",\"PV\",\"private network\"" },
  { 3232235520, "\"192.168.0.0\",\"192.168.255.255\",\"3232235520\",\"3232301055\",\"PV\",\"private network\"" },
  { 0, NULL }
};

typedef struct {
  unsigned long start;
  unsigned long end;
  char country[3];
  char c[500];
} qos_geo_t;

typedef struct {
  int num;
  char *c;
} qos_geo_stat_t;

static int qos_is_num(const char *num) {
  int i = 0;
  while(num[i]) {
    if(!isdigit(num[i])) {
      return 0;
    }
    i++;
  }
  return 1;
}

/**
 * Converts an IPv4 address string to it's numeric value.
 * w.x.y.z results in 16777216*w + 65536*x + 256*y + z
 *
 * @param pool To make a copy of the address to parse
 * @param ip
 * @return The address or 0 on error
 */
static unsigned long qos_geo_str2long(apr_pool_t *pool, const char *ip) {
  char *p;
  char *i = apr_pstrdup(pool, ip);
  unsigned long addr = 0;

  p = strchr(i, '.');
  if(!p) return 0;
  p[0] = '\0';
  if(!qos_is_num(i)) return 0;
  addr += (atol(i) * 16777216);
  i = p;
  i++;

  p = strchr(i, '.');
  if(!p) return 0;
  p[0] = '\0';
  if(!qos_is_num(i)) return 0;
  addr += (atol(i) * 65536);
  i = p;
  i++;

  p = strchr(i, '.');
  if(!p) return 0;
  p[0] = '\0';
  if(!qos_is_num(i)) return 0;
  addr += (atol(i) * 256);
  i = p;
  i++;

  if(!qos_is_num(i)) return 0;
  addr += (atol(i));

  return addr;
}

static void qos_geo_long2str(char *buf, unsigned long ip) {
  int a,b,c,d;
  a = ip % 256;
  ip = ip / 256;
  b = ip % 256;
  ip = ip / 256;
  c = ip % 256;
  ip = ip / 256;
  d = ip % 256;
  sprintf(buf, "%d.%d.%d.%d", d, c, b, a);
}

/**
 * Usage message (text or manpage format).
 */
static void usage(const char *cmd, int man) {
  if(man) {
    //.TH [name of program] [section number] [center footer] [left footer] [center header]
    printf(".TH %s 1 \"%s\" \"mod_qos utilities %s\" \"%s man page\"\n", qs_CMD(cmd), man_date,
	   man_version, cmd);
  }
  printf("\n");
  if(man) {
    printf(".SH NAME\n");
  }
  qs_man_print(man, "%s - an utility to lookup a client's country code.\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -d <path> [-l] [-s] [-ip <ip>]\n",  man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "Use this utility to resolve the country codes of IP addresses\n");
  qs_man_print(man, "within existing log files. The utility reads the log file data\n");
  qs_man_print(man, "from stdin and writes them, with the injected country code, to\n");
  qs_man_print(man, "stdout.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -d <path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifies the path to the geographical database files (CSV\n");
  qs_man_print(man, "     file containing IP address ranges and country codes).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -s\n");
  if(man) printf("\n");
  qs_man_print(man, "     Writes a summary of the requests per country only.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -l\n");
  if(man) printf("\n");
  qs_man_print(man, "     Writes the database to stdout (ignoring stdin) inserting\n");
  qs_man_print(man, "     local (127.*) and private (10.*, 172.16*, 192.168.*)\n");
  qs_man_print(man, "     network addresses.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -ip <ip>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Resolves a single IP address instead of processing a log file.\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
    printf("Reading the file access.log and adding the country code to the IP address field:\n");
    printf("\n");
  } else {
    printf("Example reading the file access.log and adding the country code to\n");
    printf("the IP address field:\n");
  }
  qs_man_println(man, "  cat access.log | %s -d GeoIPCountryWhois.csv\n", cmd);
  printf("\n");
  if(man) {
    printf("Reading the file access.log and showing a summary only:\n");
    printf("\n");
  } else {
    printf("Example reading the file access.log and showing a summary only:\n");
  }
  qs_man_println(man, "  cat access.log | %s -d GeoIPCountryWhois.csv -s\n", cmd);
  printf("\n");
  if(man) {
    printf("Resolving a single IP address:\n");
    printf("\n");
  } else {
   printf("Example resolving a single IP address:\n");
  }
  qs_man_println(man, "  %s -d GeoIPCountryWhois.csv -ip 192.84.12.23\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsfilter2(1), qsgrep(1), qshead(1), qslog(1), qslogger(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://mod-qos.sourceforge.net/\n");
  } else {
    printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  }
  if(man) {
    exit(0);
  } else {
    exit(1);
  }
}

/**
 * Comperator to search entries using bsearch.
 */
static int qos_geo_comp(const void *_pA, const void *_pB) {
  unsigned long *pA = (unsigned long *)_pA;
  qos_geo_t *pB = (qos_geo_t *)_pB;
  unsigned long search = *pA;
  if((search >= pB->start) && (search <= pB->end)) return 0;
  if(search > pB->start) return 1;
  if(search < pB->start) return -1;
  return -1; // error
}

/**
 * Loads the (sorted) CSV file into the memory.
 *
 * @param pool
 * @param db Path to the db file
 * @param size Returns the size f the db (elements in the array)
 * @param msg Error message if something got wrong
 * @return Array with all entries from the CSV file (or NULL on error)
 */
static qos_geo_t *qos_loadgeo(apr_pool_t *pool, const char *db, int *size, char **msg, int *errors) {
  regmatch_t ma[MAX_REG_MATCH];
  regex_t preg;
  regex_t pregd;
  regex_t pregext;
  qos_geo_t *geo = NULL;
  qos_geo_t *g = NULL;
  qos_geo_t *last = NULL;
  int lines = 0;
  char line[HUGE_STRING_LEN];
  char buf[HUGE_STRING_LEN];
  FILE *file;
  const qos_inj_t *inj = m_inj;
  *size = 0;
  if(regcomp(&preg, QS_GEO_PATTERN, REG_EXTENDED)) {
    // internal error
    *msg = apr_pstrdup(pool, "failed to compile regular expression "QS_GEO_PATTERN);
    (*errors)++;
    return NULL;
  }
  if(regcomp(&pregd, QS_GEO_PATTERN_D, REG_EXTENDED)) {
    // internal error
    *msg = apr_pstrdup(pool, "failed to compile regular expression "QS_GEO_PATTERN_D);
    (*errors)++;
    return NULL;
  }
  if(regcomp(&pregext, QS_GEO_PATTERN_EXT, REG_EXTENDED)) {
    // internal error
    *msg = apr_pstrdup(pool, "failed to compile regular expression "QS_GEO_PATTERN_EXT);
    (*errors)++;
    return NULL;
  }
  file = fopen(db, "r");
  if(!file) {
    (*errors)++;
    return NULL;
  }
  while(fgets(line, sizeof(line), file) != NULL) {
    if(strlen(line) > 0) {
      if(regexec(&preg, line, 0, NULL, 0) == 0) {
	lines++;
      } else {
	*msg = apr_psprintf(pool, "invalid entry in database: '%s'", line);
        (*errors)++;
        if(m_verbose) {
          char *p = *msg;
          while(p[0]) {
            if(p[0] < 32) {
              p[0] = '.';
            }
            p++;
          }
          fprintf(stderr, "line %d: %s\n", lines, *msg);
        }
      }
    }
  }
  *size = lines;
  geo = apr_pcalloc(pool, sizeof(qos_geo_t) * lines);
  g = geo;
  fseek(file, 0, SEEK_SET);
  lines = 0;
  while(fgets(line, sizeof(line), file) != NULL) {
    lines++;
    if(strlen(line) > 0) {
      int plus = 0;
      if(m_inject) {
        strcpy(buf, line);
      }
      if(regexec(&pregd, line, MAX_REG_MATCH, ma, 0) == 0) {
	plus = 1;
      }
      if(plus || regexec(&preg, line, MAX_REG_MATCH, ma, 0) == 0) {
        int missingAddr = 0;
        if(regexec(&pregext, line, 0, NULL, 0) != 0) {
          missingAddr = 1;
        }
	line[ma[1].rm_eo] = '\0';
	line[ma[2].rm_eo] = '\0';
	line[ma[3].rm_eo] = '\0';
	g->start = atoll(&line[ma[1].rm_so]);
	g->end = atoll(&line[ma[2].rm_so]);
	g->c[0] = '\0';
        if(m_inject) {
          if(inj->start && (g->start > inj->start)) {
            while(inj->start && (g->start > inj->start)) {
              printf("%s\n", inj->c);
              inj++;
            }
          } else if(g->start != inj->start) {
            if(missingAddr) {
              /* some databases do not include IP address 
                 representation (but number only) */
              char bs[128];
              char be[128];
              qos_geo_long2str(bs, g->start);
              qos_geo_long2str(be, g->end);
              printf("\"%s\",\"%s\",%s", bs, be, buf);
            }
          }
          if(!missingAddr) {
            printf("%s", buf);
          }
        }
	strncpy(g->country, &line[ma[3].rm_so], 2);
	if(last) {
	  if(g->start < last->start) {
	    *msg = apr_psprintf(pool, "wrong order/lines not sorted (line %d)", lines);
            (*errors)++;
            if(m_verbose) {
              fprintf(stderr, "line %d: wrong order/lines not sorted\n", lines);
            }
	  }
	}
	if(plus) {
	  line[ma[4].rm_eo] = '\0';
	  strncpy(g->c, &line[ma[4].rm_so], 500);
	}
	last = g;
	g++;
      }
    }
  }
  fclose(file);
  return geo;
}

int main(int argc, const char * const argv[]) {
  int errors = 0;
  int rc;
  int stat = 0;
  const char *ip = NULL;
  char *msg = NULL;
  qos_geo_t *geo;
  int size;
  const char *db = NULL;
  apr_table_t *entries;
  apr_pool_t *pool;
  const char *cmd = strrchr(argv[0], '/');
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  entries = apr_table_make(pool, 100);

  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv, "-d") == 0) {
      if (--argc >= 1) {
	db = *(++argv);
      }
    } else if(strcmp(*argv, "-ip") == 0) {
      if (--argc >= 1) {
	ip = *(++argv);
      }
    } else if(strcmp(*argv, "-s") == 0) {
      stat = 1;
    } else if(strcmp(*argv, "-l") == 0) {
      m_inject = 1;
    } else if(strcmp(*argv, "-v") == 0) {
      m_verbose = 1;
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    } else {
      usage(cmd, 0);
    }
    argc--;
    argv++;
  }

  if(db == NULL) {
    usage(cmd, 0);
  }

  rc = nice(10);
  if(rc == -1) {
    fprintf(stderr, "ERROR, failed to change nice value: %s\n", strerror(errno));
  }

  geo = qos_loadgeo(pool, db, &size, &msg, &errors);
  if(geo == NULL || msg != NULL) {
    if(msg) {
      char *p = msg;
      while(p[0]) {
        if(p[0] < 32) {
          p[0] = '.';
        }
        p++;
      }
    }
    fprintf(stderr, "failed to load database: %s (total %d errors)\n",
            msg ? msg : "-", errors);
    exit(1);
  }
  if(m_inject) {
    exit(0);
  }
  
  if(ip) {
    qos_geo_t *pB;
    unsigned long search = qos_geo_str2long(pool, ip);
    printf("search %lu: ", search);
    pB = bsearch(&search,
		 geo,
		 size,
		 sizeof(qos_geo_t),
		 qos_geo_comp);
    if(pB) {
      printf("%s\n", pB->country);
    } else {
      printf("n/a\n");
    }
    return 0;
  }

  // start reading from stdin
  {
    char prev;
    qos_geo_t *pB;
    apr_pool_t *tmp;
    char *line = calloc(1, MAX_LINE_BUFFER+1);
    regex_t preg;
    regex_t preg2;
    regmatch_t ma[MAX_REG_MATCH];
    apr_pool_create(&tmp, NULL);
    if(regcomp(&preg, IPPATTERN, REG_EXTENDED)) {
      exit(1);
    }
    regcomp(&preg2, IPPATTERN2, REG_EXTENDED);
    while(fgets(line, MAX_LINE_BUFFER, stdin) != NULL) {
      int match = regexec(&preg, line, MAX_REG_MATCH, ma, 0);
      if(match != 0) {
        char *dx = strchr(line, ';');
        if(dx && ((dx - line) <= 15)) {
          // file starts probably with <ip>; => a qslog -pc file?
          match = regexec(&preg2, line, MAX_REG_MATCH, ma, 0);
        }
      }
      if(match == 0) {
        unsigned long search;
        prev = line[ma[1].rm_eo];
        line[ma[1].rm_eo] = '\0';
        search = qos_geo_str2long(tmp, &line[ma[1].rm_so]);
        apr_pool_clear(tmp);
        pB = bsearch(&search,
                     geo,
                     size,
                     sizeof(qos_geo_t),
                     qos_geo_comp);
        if(stat) {
          /* creates a single statistic entry for each country (used to collect
             requests per source country) */
          if(pB) {
            qos_geo_stat_t *s = (qos_geo_stat_t *)apr_table_get(entries, pB->country);
            if(s == NULL) {
              s = apr_pcalloc(pool, sizeof(qos_geo_stat_t));
              s->num = 0;
              s->c = pB->c;
              apr_table_addn(entries, apr_pstrdup(pool, pB->country), (char *)s);
            }
            s->num++;
          }
        } else {
          /* modifies each log line inserting the country code
           */
          char cr = prev;
          char delw[2];
          char delx[2];
          delw[1] = '\0';
          delw[0] = ' ';
          delx[1] = '\0';
          delx[0] = ' ';
          if(line[ma[1].rm_eo+1] == ' ') {
            delx[0] = '\0';
          }
          if(line[ma[1].rm_eo+1] == ';') {
            delx[0] = ';';
          }
          if(prev <= CR) {
            prev = ' ';
          }
          if(prev == ' ') {
            delw[0] = '\0';
          }
          if(prev == ';') {
            delw[0] = '\0';
            delx[0] = ';';
          }
          if(pB) {
            printf("%s%c%s%s%s%s", line, prev,
                   delw,
                   pB->country,
                   delx,
                   &line[ma[1].rm_eo+1]);
          } else {
            printf("%s%c%s--%s%s", line, prev,
                   delw,
                   delx,
                   &line[ma[1].rm_eo+1]);
          }
          if(cr <= CR) {
            printf("\n");
          }
        }
      } else {
        printf("%s", line);
      }
      fflush(stdout);
    }
    if(stat) {
      int i;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(entries)->elts;
      for(i = 0; i < apr_table_elts(entries)->nelts; i++) {
	qos_geo_stat_t *s = (qos_geo_stat_t *)entry[i].val;
	printf("%7.d %s %s\n", s->num, entry[i].key, s->c ? s->c : "");
      }
    }
  }
  return 0;
}
