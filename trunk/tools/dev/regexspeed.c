/**
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2015 Pascal Buchbinder
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

static const char revision[] = "$Revision: 1.12 $";

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
#define LOOPS 100

typedef struct {
  pcre *pc;
  pcre_extra *extra;
} rule_t;

static void usage2() {
  printf("usage: regex <path to pattern file>\n");
  exit(1);
}

typedef struct {
  const char* string;
  int len;
} qs_r_t;

int main(int argc, const char *const argv[]) {
  int datalen=0;
  qs_r_t data[] = {
    { "Emma", 0 },
    { "Buchschacher", 0 },
    { "Schafhauserstrasse 60, 8000 Zürich", 0 },
    { "128128127136178267893209807237276365235", 0 },
    { "/get/application/data/index/list/all/data", 0 },
    { "05.03.1978", 0 },
    { "888 888-888-777", 0 },
    { "lajksdfhjklasdhfaskdjfhklasjdlfaksdhfasjkdflsajkdflkdflhdjklfadhfksdjfhklasjdhfskljdfhsklajdhflskjdfhlskjhdflksjdhlfksjdhfjklsdhfklsdhfklsjdhklshlksfhdklfhslkdfhlskhdklsjhdflskfhlsh", 0 },
    { "ajksdfhjklasdhfaskdjfhklasjdlfaksdhfasjkdflsajkdflkdflhdjklfadhfksdjfhklasjdhfskljdfhsklajdhflskjdfhlskjhdflksjdhlfksjdhfjklsdhfklsdhfklsjdhklshlksfljsdahsdznvztbasmuiwmereizfrbizvnsdmovosduvnuztbvzucxzvmpmvdzubtfrmeirmrnbewrJHJSBNUAIMSODMAINBSUDTAZSUDIOASMDNBAGZDTSZBUANIMOINSAUBZDGTZUIOIMSKNABJDHT9807765243567283992039209376526368799230827836526789 ç%&/\"(><<<-.,:;)*=)()(&%\"ç", 0 },
    { "    To be, or not to be: that is the question:    Whether 'tis nobler in the mind to suffer The slings and arrows of outrageous fortune, Or to take arms against a sea of troubles, And by opposing end them? To die: to sleep; No more; and by a sleep to say we end The heart-ache and the thousand natural shocks That flesh is heir to, 'tis a consummation Devoutly to be wish'd. To die, to sleep; To sleep: perchance to dream: ay, there's the rub; For in that sleep of death what dreams may come When we have shuffled off this mortal coil, Must give us pause: there's the respect That makes calamity of so long life; For who would bear the whips and scorns of time, The oppressor's wrong, the proud man's contumely, The pangs of despised love, the law's delay, The insolence of office and the spurns That patient merit of the unworthy takes, When he himself might his quietus make With a bare bodkin? who would fardels bear, To grunt and sweat under a weary life, But that the dread of something after death, The undiscover'd country from whose bourn No traveller returns, puzzles the will And makes us rather bear those ills we have Than fly to others that we know not of? Thus conscience does make cowards of us all; And thus the native hue of resolution Is sicklied o'er with the pale cast of thought, And enterprises of great pith and moment With this regard their currents turn awry, And lose the name of action.--Soft you now! The fair Ophelia! Nymph, in thy orisonsBe all my sins remember'd.", 0 },
    { "{\n" \
  "    \"_to\": \"1.2.3.4:5678\",\n"		\
  "    \"_line\": 63546230,\n"						\
  "    \"profile_image_url\": \"http://a3.twimg.com/profile_images/852841481/Untitled_3_normal.jpg\",\n" \
  "    \"created_at\": \"Sat, 08 May 2010 21:46:23 +0000\",\n"		\
  "    \"from_user\": \"pelchiie\",\n"					\
  "    \"metadata\": {\n"						\
  "        \"result_type\": \"recent\"\n"				\
  "    },\n"								\
  "    \"to_user_id\": null,\n"						\
  "    \"text\": \"twitter is dead today.\",\n"				\
  "    \"id\": 13630378882,\n"						\
  "    \"from_user_id\": 12621761,\n"					\
  "    \"geo\": null,\n"						\
  "    \"iso_language_code\": \"en\",\n"				\
  "    \"source\": \"<a href=\\\"http://twitter.com/\\\">web</a>\"\n"	\
      "}", 0 },
    { NULL, 0 }
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

  {
    // init
    qs_r_t *d = data;
    while(d->string) {
      d->len = strlen(d->string);
      datalen += d->len;
      d++;
    }
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
      if(strlen(readline) > 0) {
	p = readline;
	if(strncmp(p, "ch.nev", 6) == 0) {
	  int itr = 4;
	  if(strstr(p, "DecodingRules") == 0) {
	    itr = 2;
	  }
	  for(; itr > 0; itr--) {
	    char *px = strchr(p, ':');
	    if(px) {
	      p = &px[1];
	    }
	  }
	}
	//p++;
	//len = strlen(p);
	//p[len-1] = '\0';
	rule->pc = pcre_compile(p, PCRE_DOTALL|PCRE_CASELESS, &errptr, &erroffset, NULL);
	if(rule->pc == NULL) {
	  printf("faild to compile pattern [%s], reason: %s\n", p, errptr);
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
  }

  { // per rule
      int k;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
      for(k = 0; k < apr_table_elts(rules)->nelts; k++) {
	qs_r_t *d = data;
	rule_t* rule = (rule_t *)entry[k].val;
	gettimeofday(&tv, NULL);
	start = tv.tv_sec * 1000000 + tv.tv_usec;
	while(d->string) {
	  pcre_exec(rule->pc, rule->extra, d->string, d->len, 0, 0, NULL, 0);
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
    const qs_r_t *d = data;
    while(d->string) {
      int k;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
      for(k = 0; k < apr_table_elts(rules)->nelts; k++) {
	rule_t* rule = (rule_t *)entry[k].val;
	pcre_exec(rule->pc, rule->extra, d->string, d->len, 0, 0, NULL, 0);
      }
      d++;
    }
  }
  gettimeofday(&tv, NULL);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  printf("match all rules (%d) against the test variables (%d strings, %d characters) took: %lld usec (%s)\n",
	 apr_table_elts(rules)->nelts,
	 sizeof(data)/sizeof(qs_r_t)-1, datalen,
	 (end - start) / LOOPS,
	 revision);
  return 0;

}
