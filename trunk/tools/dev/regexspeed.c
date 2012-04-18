/**
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

static const char revision[] = "$Id: regexspeed.c,v 1.3 2012-04-18 20:38:03 pbuchbinder Exp $";

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* OpenSSL  */
#include <openssl/stack.h>

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
#define QS_OVECCOUNT 100
#define LOOPS 10

typedef struct {
  pcre *pc;
  pcre_extra *extra;
} rule_t;

static void usage2() {
  printf("usage: regex <path to pattern file>\n");
  exit(1);
}

int main(int argc, const char *const argv[]) {
  const char *data[] = {
    "Emma",
    "Buchschacher",
    "Schafhauserstrasse 60, 8000 Zürich",
    "128128127136178267893209807237276365235",
    "/get/application/data/index/list/all/data",
    "05.03.1978",
    "888 888-888-777",
    "lajksdfhjklasdhfaskdjfhklasjdlfaksdhfasjkdflsajkdflkdflhdjklfadhfksdjfhklasjdhfskljdfhsklajdhflskjdfhlskjhdflksjdhlfksjdhfjklsdhfklsdhfklsjdhklshlksfhdklfhslkdfhlskhdklsjhdflskfhlsh",
    "ajksdfhjklasdhfaskdjfhklasjdlfaksdhfasjkdflsajkdflkdflhdjklfadhfksdjfhklasjdhfskljdfhsklajdhflskjdfhlskjhdflksjdhlfksjdhfjklsdhfklsdhfklsjdhklshlksfljsdahsdznvztbasmuiwmereizfrbizvnsdmovosduvnuztbvzucxzvmpmvdzubtfrmeirmrnbewrJHJSBNUAIMSODMAINBSUDTAZSUDIOASMDNBAGZDTSZBUANIMOINSAUBZDGTZUIOIMSKNABJDHT9807765243567283992039209376526368799230827836526789 ç%&/\"(><<<-.,:;)*=)()(&%\"ç",
    NULL
  };
  int i;
  FILE *file;
  apr_pool_t *pool;
  apr_table_t *rules;
  long long start;
  long long end;
  struct timeval tv;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  rules = apr_table_make(pool, 100);

  if(argc != 2) {
    usage2();
  }

  file = fopen(argv[1], "r");
  if(file) {
    char readline[MAX_LINE];
    while(fgets(readline, MAX_LINE-1, file) != NULL) {
      char *p;
      int len = strlen(readline);
      const char *errptr = NULL;
      int erroffset;
      rule_t *rule = apr_pcalloc(pool, sizeof(rule_t));
      while(len > 0 && readline[len] < 32) {
	readline[len] = '\0';
	len--;
      }
      p = readline;
      //p++;
      //len = strlen(p);
      //p[len-1] = '\0';
      rule->pc = pcre_compile(p, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
      if(rule->pc == NULL) {
	printf("faild to compile pattern %s\n", p);
	exit(1);
      }
      rule->extra = pcre_study(rule->pc, 0, &errptr);
      if(rule->extra == NULL) {
        rule->extra = apr_pcalloc(pool, sizeof(pcre_extra));
      }
      rule->extra->match_limit = 1500;
      rule->extra->flags |= PCRE_EXTRA_MATCH_LIMIT;
      apr_table_addn(rules, apr_pstrdup(pool, p), (char *)rule);
    }
  }

  { // per rule
      int k;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
      for(k = 0; k < apr_table_elts(rules)->nelts; k++) {
	const char **d = data;
	rule_t* rule = (rule_t *)entry[k].val;
	gettimeofday(&tv, NULL);
	start = tv.tv_sec * 1000000 + tv.tv_usec;
	while(*d) {
	  pcre_exec(rule->pc, rule->extra, *d, strlen(*d), 0, 0, NULL, 0);
	  d++;
	}
	gettimeofday(&tv, NULL);
	end = tv.tv_sec * 1000000 + tv.tv_usec;
	printf("%lld usec for %s\n", end - start, entry[k].key);	
      }
  }

  // all rules
  gettimeofday(&tv, NULL);
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  for(i = 0; i < LOOPS; i++) {
    const char **d = data;
    while(*d) {
      int k;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
      for(k = 0; k < apr_table_elts(rules)->nelts; k++) {
	rule_t* rule = (rule_t *)entry[k].val;
	pcre_exec(rule->pc, rule->extra, *d, strlen(*d), 0, 0, NULL, 0);
      }
      d++;
    }
  }
  gettimeofday(&tv, NULL);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  printf("match all rules against the test variables (%d strings) took: %lld usec\n",
	 sizeof(data)/sizeof(char *)-1,
	 (end - start) / LOOPS);
  return 0;
}
