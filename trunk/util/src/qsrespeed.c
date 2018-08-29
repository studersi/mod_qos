/**
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2018 Pascal Buchbinder
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

static const char revision[] = "$Revision$";

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* apr */
#include <pcre.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>

#include "qs_util.h"

#define LOOPS 100

typedef struct {
  pcre *pc;
  pcre_extra *extra;
  const char *id;
} rule_t;

static void usage2() {
  printf("usage: regexspeed <path to pattern file>\n");
  printf("\n");
  printf("Tool to compare / estimate the processing time for (Perl-compatible)\n");
  printf("regular expressions (PCRE).\n");
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
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
    { "name=value&id=kAfBFLJaBQB-AAABBQAAAAZgAAAA9--DwnTUWct-AAA2&host=me.main.org&key=121213122aaaaaaaaaaMMMM123&tex=emb+ed", 0 },
    { "<x:ml><node attribute=\"value\" attr2=\"99999999\">text shows_this!</node></x:ml>", 0 },
    { "lajksdfhjklasdhfaskdjfhklasjdlfaksdhfasjkdflsajkdflkdflhdjklfadhfksdjfhklasjdhfskljdfhsklajdhflskjdfhlskjhdflksjdhlfksjdhfjklsdhfklsdhfklsjdhklshlksfhdklfhslkdfhlskhdklsjhdflskfhlsh", 0 },
    { "ajksdfhjklasdhfaskdjfhklasjdlfaksdhfasjkdflsajkdflkdflhdjklfadhfksdjfhklasjdhfskljdfhsklajdhflskjdfhlskjhdflksjdhlfksjdhfjklsdhfklsdhfklsjdhklshlksfljsdahsdznvztbasmuiwmereizfrbizvnsdmovosduvnuztbvzucxzvmpmvdzubtfrmeirmrnbewrJHJSBNUAIMSODMAINBSUDTAZSUDIOASMDNBAGZDTSZBUANIMOINSAUBZDGTZUIOIMSKNABJDHT9807765243567283992039209376526368799230827836526789 ç%&/\"(><<<-.,:;)*=)()(&%\"ç", 0 },
    { "text/html,application/xhtml+xm…plication/xml;q=0.9,*/*;q=0.8", 0 },
    { "Accept-Language: fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5", 0},
    { "Hm_lvt_ef1299edab2ff5d2f13e859…d=GA1.2.1594867574.1516566392", 0 },
    { "If-Modified-Since", 0 },
    { "Fri, 05 Jan 2018 02:34:41 GMT", 0 },
    { "[Wed Feb 28 22:08:09 2018] [notice] Apache/2.2.34 (Unix) mod_ssl/2.2.34 OpenSSL/1.0.2g mod_qos/11.52 configured -- resuming normal operations", 0 },
    { "127.0.0.1 - - [28/Feb/2018:21:03:37 +0100] \"GET /console?action=inclimit&address=194.31.217.21&event=QS_Limit HTTP/1.1\" 200 52 \"-\" 0 - - - id=wWkYPUtmBQARFAABEAAAAAAX-yQgC5d2 - - #5230", 0 },
    { "2013/11/07 17:44:07 [error] 4640#0: *55 auth_token_module(014): request not authorized: invalid signature, client: 127.0.0.1, server: localhost, request: \"GET /app/index.html?req=1 HTTP/1.1\", host: \"127.0.0.1:8204\" 000000000002#IPhzBRn7cuuGdqBI7T4OSIjXx7JGliUokCk8dFIU9n0=", 0 },
    { "2010 12 04 20:46:45.118 dispatch   IWWWauthCo 07148.4046314384 3-ERROR :  AuthsessClient_1_0::execute: no valid 000000000002#5jYHrFBotkZwAs5EyfVQVgNZb3M=", 0 },
    { "2011-09-01 07:37:17,275 main            org.apache.catalina.startup.Catalina     INFO  Server startup in 5770 ms 000000000002#LQ/h2UbJ2HzdZyf8BqnB7TB8LZM=", 0 },
    { "2010-04-14 20:18:37,464 | INFO  | org.hibernate.cfg         ::getInputStream:1081  resource: /hibernate.cfg.xml 000000000002#9lpZof9jvdMRrIebCM7rbKzJ7aY=", 0 },
    { "http://mod-qos.sourceforge.net/", 0 },
    { "Mozilla/5.0 (X11; Ubuntu; Linu…) Gecko/20100101 Firefox/57.0", 0 },
    { "           Whether 'tis nobler in the mind to suffer The slings and arrows of outrageous fortune, Or to take arms against a sea of troubles, And by opposing end them? To die: to sleep; No more; and by a sleep to say we end The heart-ache and the thousand natural shocks That flesh is heir to, 'tis a consummation Devoutly to be wish'd.", 0 },
    { "To be, or not to be: that is the question:    Whether 'tis nobler in the mind to suffer The slings and arrows of outrageous fortune, Or to take arms against a sea of troubles, And by opposing end them? To die: to sleep; No more; and by a sleep to say we end The heart-ache and the thousand natural shocks That flesh is heir to, 'tis a consummation Devoutly to be wish'd. To die, to sleep; To sleep: perchance to dream: ay, there's the rub; For in that sleep of death what dreams may come When we have shuffled off this mortal coil, Must give us pause: there's the respect That makes calamity of so long life; For who would bear the whips and scorns of time, The oppressor's wrong, the proud man's contumely, The pangs of despised love, the law's delay, The insolence of office and the spurns That patient merit of the unworthy takes, When he himself might his quietus make With a bare bodkin? who would fardels bear, To grunt and sweat under a weary life, But that the dread of something after death, The undiscover'd country from whose bourn No traveller returns, puzzles the will And makes us rather bear those ills we have Than fly to others that we know not of? Thus conscience does make cowards of us all; And thus the native hue of resolution Is sicklied o'er with the pale cast of thought, And enterprises of great pith and moment With this regard their currents turn awry, And lose the name of action.--Soft you now! The fair Ophelia! Nymph, in thy orisonsBe all my sins remember'd.", 0 },
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
      rule->id = NULL;
      while(len > 0 && readline[len] < 32) {
	readline[len] = '\0';
	len--;
      }
      if((strlen(readline) > 0) &&
	 (readline[0] != 10) &&
	 (readline[0] != 13)) {
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
	      if(rule->id == NULL) {
		char *end;
		rule->id = apr_pstrdup(pool, p);
		end = strchr(rule->id, ':');
		if(end) {
		  end[0] = '\0';
		}
	      }
	    }
	  }
	}

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
  } else {
    usage2();
  }

  { // per rule
      int k;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(rules)->elts;
      for(k = 0; k < apr_table_elts(rules)->nelts; k++) {
	rule_t* rule = (rule_t *)entry[k].val;
	gettimeofday(&tv, NULL);
	start = tv.tv_sec * 1000000 + tv.tv_usec;
	for(i = 0; i < LOOPS; i++) {
	  qs_r_t *d = data;
	  while(d->string) {
	    pcre_exec(rule->pc, rule->extra, d->string, d->len, 0, 0, NULL, 0);
	    d++;
	  }
	}
	gettimeofday(&tv, NULL);
	end = tv.tv_sec * 1000000 + tv.tv_usec;
	printf("%lld usec for %s\n", (end - start)/LOOPS, rule->id != NULL ? rule->id : entry[k].key);	
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
  printf("match all rules (%d) against the test variables (%lu strings, %d characters) took: %lld usec (%s/PCRE %s)\n",
	 apr_table_elts(rules)->nelts,
	 sizeof(data)/sizeof(qs_r_t)-1,
	 datalen,
	 (end - start) / LOOPS,
	 revision, pcre_version());
  return 0;

}
