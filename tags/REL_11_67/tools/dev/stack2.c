/**
 * Utilities for the quality of service module mod_qos.
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
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <apr.h>
#include <apr_strings.h>

#define QSMOD 4
#define LIMIT 1

static int m_qsmod = QSMOD;
static int m_silent = 0;

typedef struct {
  short int limit;
  time_t limit_time;
} qos_s_entry_limit_t;

typedef struct {
  unsigned long ip;
  unsigned long ip6;
  time_t lowrate;
  /* behavior */
  unsigned int html;
  unsigned int cssjs;
  unsigned int img;
  unsigned int other;
  unsigned int notmodified;
  unsigned int serialize;
  unsigned int events;
  /* prefer */
  short int vip;
  /* ev block */
  short int block;
  short int blockMsg;
  time_t time;
  time_t block_time;
  qos_s_entry_limit_t *limit;
  /* ev/sec */
  time_t interval;
  long req;
  long req_per_sec;
  int req_per_sec_block_rate;
  int event_req;
} qos_s_entry_t;

typedef struct {
  time_t t;
  qos_s_entry_t **ipd;
  qos_s_entry_t **timed;
  int num;
  int max;
  int msize;
} qos_s_t;


static int qoss_comp(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->ip > pB->ip) return 2;
  if(pA->ip < pB->ip) return -2;
  if(pA->ip6 > pB->ip6) return 1;
  if(pA->ip6 < pB->ip6) return -1;
  return 0;
}

static int qoss_comp_time(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->time > pB->time) return 1;
  if(pA->time < pB->time) return -1;
  return 0;
}

static qos_s_t *qoss_new(int size) {
  int lsize = (sizeof(qos_s_entry_limit_t) * LIMIT * size);
  int msize = sizeof(qos_s_t) + 
    (sizeof(qos_s_entry_t) * size) + 
    (2 * sizeof(qos_s_entry_t *) * size);
  int i;
  qos_s_t *s = calloc(msize, 1);
  qos_s_entry_t *e = (qos_s_entry_t *)&s[1];
  qos_s_entry_limit_t *l = calloc(lsize, 1);
  s->ipd = (qos_s_entry_t **)&e[size];
  s->timed = (qos_s_entry_t **)&s->ipd[size];
  s->num = 0;
  s->max = size;
  s->msize = msize + lsize;
  for(i = 0; i < size; i++) {
    s->ipd[i] = e;
    s->timed[i] = e;
    e->limit = l;
    e++;
    l++;
  }
  return s;
}

static void qoss_free(qos_s_t *s) {
  free(s);
}

/**
 * gets an entry by its ip
 */
static qos_s_entry_t **qoss_get0(qos_s_t *s, qos_s_entry_t *pA, time_t now) {
  qos_s_entry_t **pB;
  int mod = pA->ip % m_qsmod;
  int max = (s->max / m_qsmod);
  int start = mod * max;
  pB = bsearch((const void *)&pA, (const void *)&s->ipd[start], max, sizeof(qos_s_entry_t *), qoss_comp);
  if(pB) {
    if(now != 0) {
      s->t = now;
    }
    (*pB)->time = s->t;
  }
  return pB;
}

static void qoss_sort(qos_s_t *s) {
  int i;
  for(i = 0; i < m_qsmod; i++) {
    int mod = i % m_qsmod;
    int max = (s->max / m_qsmod);
    int start = mod * max;
    qsort(&s->ipd[start],max, sizeof(qos_s_entry_t *), qoss_comp);
    qsort(&s->timed[start], max, sizeof(qos_s_entry_t *), qoss_comp_time);
  }
}

static void qoss_set(qos_s_t *s, qos_s_entry_t *pA, time_t now) {
  qos_s_entry_t **pB;
  int mod = pA->ip % m_qsmod;
  int max = (s->max / m_qsmod);
  int start = mod * max;
  s->t = now;
  qsort(&s->timed[start], max, sizeof(qos_s_entry_t *), qoss_comp_time);
  if(s->num < s->max) {
    s->num++;
  }
  pB = &s->timed[start];
  (*pB)->ip = pA->ip;
  (*pB)->ip6 = pA->ip6;
  (*pB)->time = now;
  qsort(&s->ipd[start], max, sizeof(qos_s_entry_t *), qoss_comp);

  (*pB)->block = 0;
  (*pB)->blockMsg = 0;
  (*pB)->block_time = 0;
}

static void qoss_set_fast(qos_s_t *s, qos_s_entry_t *pA, long i) {
  qos_s_entry_t **pB;
  int mod = pA->ip % m_qsmod;
  int max = (s->max / m_qsmod);
  int start = mod * max;
  if(s->num <= s->max) {
    pB = &s->timed[start + i/m_qsmod];
    (*pB)->ip = pA->ip;
    (*pB)->ip6 = pA->ip6;
    (*pB)->time = time(NULL);
    s->num++;
  } else {
    printf("ERROR! no more free slots\n");
    exit(1);
  }
}

static void speed(long size) {
  qos_s_entry_t new;
  qos_s_t *s = qoss_new(size);
  qos_s_entry_t **e = NULL;
  long i;
  struct timeval tv;
  long long start;
  long long average = 0;
  long items[] = { 12, 48333, size-2, size-1000, size/2, size/8, 9827, 25998, 77, 58 };

  printf("> memory size=%dMbytes entries=%d (%d): %d bytes per client\n",
	 s->msize / 1024 / 1024,
	 s->max, m_qsmod, s->msize/s->max);

  new.ip = 0;
  new.ip6 = 0;
  qoss_set(s, &new, time(NULL));
  for(i = 0; i < size; i++) {
    new.ip = i;
    qoss_set_fast(s, &new, i);
  }
  i--;
  if(!m_silent) {
    printf("added: 0 to %ld\n", i);
  }
  qoss_sort(s);
  
  /* get */
  for(i = 0; i < (sizeof(items)/sizeof(long)); i++) {
    new.ip = items[i];
    gettimeofday(&tv, NULL);
    start = tv.tv_sec * 1000000 + tv.tv_usec;
    e = qoss_get0(s, &new, 0);
    gettimeofday(&tv, NULL);
    if(e == NULL) {
      printf("ERROR, %ld not found\n", new.ip);
      exit(1);
    } else {
      if(!m_silent) {
	printf("get:   %.6lld usec (%ld)\n", (tv.tv_sec * 1000000 + tv.tv_usec) - start, (*e)->ip);
      }
      average = average + (tv.tv_sec * 1000000 + tv.tv_usec) - start;
    }
  }
  printf("get     mod=%d size=%ld:\t average %.6lld usec\n", m_qsmod, size, average / i);
  average = 0;
  

  /* set */
  sleep(1); // those entries are newer
  for(i = 0; i < (sizeof(items)/sizeof(long)); i++) {
    new.ip = items[i]+50000;
    gettimeofday(&tv, NULL);
    start = tv.tv_sec * 1000000 + tv.tv_usec;
    qoss_set(s, &new, time(NULL));
    gettimeofday(&tv, NULL);
    if(!m_silent) {
      printf("set:   %.6lld usec (%ld)\n", (tv.tv_sec * 1000000 + tv.tv_usec) - start, new.ip);
    }
    average = average + (tv.tv_sec * 1000000 + tv.tv_usec) - start;
  }
  printf("set     mod=%d size=%ld:\t average %.6lld usec\n", m_qsmod, size, average / i);

  for(i = 0; i < (sizeof(items)/sizeof(long)); i++) {
    new.ip = items[i]+50000;
    e = qoss_get0(s, &new, 0);
    if(e == NULL) {
      printf("ERROR, %ld not found\n", new.ip);
      exit(1);
    }
  }

  qoss_free(s);
}

static void func() {
  int m;
  int size = 12;
  qos_s_entry_t new;
  qos_s_t *s = qoss_new(size);
  qos_s_entry_t **e = NULL;
  int i;
  unsigned long v = 0;
  unsigned long ar[] = { 1, 5, 6, 7, 8, 9, 10, 100 };
  printf("> %d %d: %d bytes per client\n", s->msize, s->max, s->msize/s->max);
  new.ip6=0;
  for(i = 0; i < sizeof(ar)/sizeof(unsigned long); i++) {
    new.ip = ar[i];
    e = qoss_get0(s, &new, 0);
    if(!e) {
      printf("[%lu]", new.ip); fflush(stdout);
      sleep(1);
      qoss_set(s, &new, time(NULL));
    }
  }
  printf("\n");
  qoss_sort(s);
  for(i = 0; i < s->max; i++) {
    e = &s->timed[i];
    printf("pos=%d %lu %lu\n", i, (*e)->ip, (*e)->time);
  }
  for(i = 0; i < sizeof(ar)/sizeof(unsigned long); i++) {
    new.ip = ar[i];
    e = qoss_get0(s, &new, 0);
    if(!e) {
      printf("ERROR-1 pos=%d %lu\n", i, new.ip); fflush(stdout);
      exit(1);
    }
  }
  /* oldest first */
  for(m = 0; m < m_qsmod; m++) {
    v = 0;
    for(i = (m * s->max/m_qsmod); i < (m+1) * (s->max/m_qsmod); i++) {
      e = &s->timed[i];
      printf("pos=%d %lu %lu\n", i, (*e)->ip, (*e)->time);
      if(v > (*e)->time) {
	printf("ERROR-2 pos=%d %lu\n", i, (*e)->time); fflush(stdout);
	exit(1);
      }
      v = (*e)->time;
    }
  }
  /* lowest first */
  for(m = 0; m < m_qsmod; m++) {
    v = 0;
    for(i = (m * s->max/m_qsmod); i < (m+1) * (s->max/m_qsmod); i++) {
      e = &s->ipd[i];
      if((*e)->ip < v) {
	printf("ERROR-2 pos=%d %lu\n", i, (*e)->ip); fflush(stdout);
	exit(1);
      }
      v = (*e)->ip;
    }
  }
  qoss_free(s);
}

static char *qos_ip_long2str(apr_pool_t *pool, const void *src) {
  char *dst = apr_pcalloc(pool, INET6_ADDRSTRLEN);
  return (char *)inet_ntop(AF_INET6, src, dst, INET6_ADDRSTRLEN);
}

static int qos_ip_str2long(const char *src, void *dst) {
  char str[INET6_ADDRSTRLEN];
  const char *convert = src;
  unsigned long *n = dst;
  n[0] = 0;
  n[1] = 0;
  if(convert == NULL) {
    return 0;
  }
  if((strchr(convert, ':') == NULL) && 
     (strlen(convert) <= 15)) {
    // looks like an IPv4 address
    sprintf(str, "::ffff:%s", src);
    convert = str;
  }
  return inet_pton(AF_INET6, convert, dst);
}

static void segm() {
  unsigned char *b;
  int i, j, k, l;
  int crm[m_qsmod];
  int tot = 0;
  for(i = 0; i < m_qsmod; i++) {
    crm[i] = 0;
  }
  for(i = 125; i < (125 + m_qsmod); i++) {
    for(j = 0; j < (6 + m_qsmod); j++) {
      for(k = 0; k < (46 + m_qsmod); k++) {
	for(l = 1; l < (22 + m_qsmod); l++) {
	  char str[INET6_ADDRSTRLEN];
	  unsigned long dst[2];
	  int cr = 0;
	  tot++;
	  sprintf(str, "%d.%d.%d.1%d", i, j, k, l);
	  //printf("%s\n", str);
	  if(qos_ip_str2long(str, &dst) == 0) {
	    printf("ERROR %s\n", str);
	    exit(1);
	  }
	  b = (void *)&dst[1];
	  cr = b[7] % m_qsmod;
	  crm[cr]++;
	}
      }
    }
  }
  printf("mod %d", m_qsmod);
  for(i = 0; i < m_qsmod; i++) {
    printf(" %d", crm[i]);
  }
  printf(" total=%d\n", tot);
}

int main(int argc, const char * const argv[]) {
  char *str;
  apr_pool_t *pool;
  unsigned long dst[2];
  int rc;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  rc = qos_ip_str2long("fe80::250:56ff:fec0:8", &dst);
  printf("%d %lu %lu\n", rc, dst[0], dst[1]);
  str = qos_ip_long2str(pool, dst);
  printf("%d %s\n", rc, str);

  rc = qos_ip_str2long("fc00::112", &dst);
  printf("%d %lu %lu\n", rc, dst[0], dst[1]);
  str = qos_ip_long2str(pool, dst);
  printf("%d %s\n", rc, str);

  rc = qos_ip_str2long("fc00::111", &dst);
  printf("%d %lu %lu\n", rc, dst[0], dst[1]);
  str = qos_ip_long2str(pool, dst);
  printf("%d %s\n", rc, str);

  rc = qos_ip_str2long("127.0.0.1", &dst);
  printf("%d %lu %lu (%d)\n", rc, dst[0], dst[1], inet_addr("127.0.0.1"));
  str = qos_ip_long2str(pool, dst);
  printf("%d %s\n", rc, str);

  rc = qos_ip_str2long("gaga", &dst);
  printf("%d %lu %lu\n", rc, dst[0], dst[1]);
  str = qos_ip_long2str(pool, dst);
  printf("%d %s\n", rc, str);

  m_qsmod = 2;
  segm();
  m_qsmod = 4;
  segm();
  m_qsmod = 8;
  segm();
  m_qsmod = 16;
  segm();
  m_qsmod = 32;
  segm();
  m_qsmod = QSMOD;

  func();
  printf("\n"); 
  m_qsmod = 1;
  speed(50000);
  m_silent = 1;
  m_qsmod = 2;
  speed(50000);
  m_qsmod = 4;
  speed(50000);
  m_qsmod = 8;
  speed(50000);
  m_qsmod = 8;
  speed(100000);
  m_qsmod = 16;
  speed(100000);
  m_qsmod = 16;
  speed(500000);
  m_qsmod = 32;
  speed(1000000);
  m_qsmod = 32;
  speed(2000000);
  m_qsmod = 32;
  speed(10000000);

  return 0;
}
