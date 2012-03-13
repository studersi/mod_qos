/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2012 Pascal Buchbinder
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

static const char revision[] = "$Id: geo.c,v 1.7 2012-02-04 16:31:25 pbuchbinder Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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

#define QOSCR    13
#define QOSLF    10
#define MAX_REG_MATCH 10

// "3758096128","3758096383","AU"
#define QS_GEO_PATTERN "\"([0-9]+)\",\"([0-9]+)\",\"([A-Z0-9]{2})\""
#define IPPATTERN "([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})[\"' ]+"

typedef struct {
  unsigned long start;
  unsigned long end;
  char country[3];
} qos_geo_t;

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

/*
static char *qos_geo_long2str(apr_pool_t *pool, unsigned long ip) {
  int a,b,c,d;
  a = ip % 256;
  ip = ip / 256;
  b = ip % 256;
  ip = ip / 256;
  c = ip % 256;
  ip = ip / 256;
  d = ip % 256;
  return apr_psprintf(pool, "%d.%d.%d.%d", d, c, b, a);
}
*/

static void usage(const char *cmd) {
  printf("\n");
  printf("Usage: %s <path>\n", cmd);
  printf("\n");
  printf("Example:\n");
  printf("\n");
  printf("  cat access_log | ./geo -d GeoIPCountryWhois.csv\n");
  printf("\n");
  exit(1);
}

static int qos_geo_comp(const void *_pA, const void *_pB) {
  unsigned long *pA = (unsigned long *)_pA;
  qos_geo_t *pB = (qos_geo_t *)_pB;
  unsigned long search = *pA;
  if((search >= pB->start) && (search <= pB->end)) return 0;
  if(search > pB->start) return 1;
  if(search < pB->start) return -1;
  return -1; // error
}

static qos_geo_t *qos_loadgeo(apr_pool_t *pool, const char *db, int *size, char **msg) {
  regmatch_t ma[MAX_REG_MATCH];
  regex_t preg;
  qos_geo_t *geo = NULL;
  qos_geo_t *g = NULL;
  qos_geo_t *last = NULL;
  int lines = 0;
  char line[HUGE_STRING_LEN];
  FILE *file = fopen(db, "r");
  *size = 0;
  if(!file) {
    return NULL;
  }
  if(regcomp(&preg, QS_GEO_PATTERN, REG_EXTENDED)) {
    *msg = apr_pstrdup(pool, "failed to compile regular expression "QS_GEO_PATTERN);
    return NULL;
  }
  while(fgets(line, sizeof(line), file) != NULL) {
    if(strlen(line) > 0) {
      if(regexec(&preg, line, 0, NULL, 0) == 0) {
	lines++;
      } else {
	*msg = apr_psprintf(pool, "invalid entry in database: '%s'", line);
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
      if(regexec(&preg, line, MAX_REG_MATCH, ma, 0) == 0) {
	line[ma[1].rm_eo] = '\0';
	line[ma[2].rm_eo] = '\0';
	line[ma[3].rm_eo] = '\0';
	g->start = atoll(&line[ma[1].rm_so]);
	g->end = atoll(&line[ma[2].rm_so]);
	strncpy(g->country, &line[ma[3].rm_so], 2);
	if(last) {
	  if(g->start < last->start) {
	    *msg = apr_psprintf(pool, "wrong order/lines not storted (line %d)", lines);
	  }
	}
	last = g;
	g++;
      }
    }
  }
  return geo;
}

int main(int argc, const char * const argv[]) {
  const char *ip = NULL;
  char *msg = NULL;
  qos_geo_t *geo;
  int size;
  const char *db = NULL;
  apr_pool_t *pool;
  const char *cmd = strrchr(argv[0], '/');
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
    if(strcmp(*argv, "-d") == 0) {
      if (--argc >= 1) {
	db = *(++argv);
      }
    } else if(strcmp(*argv, "-ip") == 0) {
      if (--argc >= 1) {
	ip = *(++argv);
      }
    } else {
      usage(cmd);
    }
    argc--;
    argv++;
  }

  if(db == NULL) {
    usage(cmd);
  }

  geo = qos_loadgeo(pool, db, &size, &msg);
  if(geo == NULL) {
    fprintf(stderr, "failed to load database: %s\n", msg ? msg : "-");
    exit(1);
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
    char line[HUGE_STRING_LEN];
    regex_t preg;
    regmatch_t ma[MAX_REG_MATCH];
    apr_pool_create(&tmp, NULL);
    if(regcomp(&preg, IPPATTERN, REG_EXTENDED)) {
      exit(1);
    }
    while(fgets(line, sizeof(line), stdin) != NULL) {
      if(regexec(&preg, line, MAX_REG_MATCH, ma, 0) == 0) {
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
	if(pB) {
	  printf("%s%c%s%s %s", line, prev, prev == ' ' ? "" : " ", pB->country, &line[ma[1].rm_eo+1]);
	} else {
	  printf("%s%c%s-- %s", line, prev, prev == ' ' ? "" : " ", &line[ma[1].rm_eo+1]);
	}
      }
    }
  }
  return 0;
}