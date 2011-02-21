/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2008 Pascal Buchbinder
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

static const char revision[] = "$Id: stack.c,v 1.22 2011-02-21 21:19:11 pbuchbinder Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

typedef struct {
  unsigned long ip;
  time_t lowrate;
  /* behavior */
  unsigned int html;
  unsigned int cssjs;
  unsigned int img;
  unsigned int other;
  unsigned int notmodified;
  unsigned int serialize;
  /* prefer */
  short int vip;
  /* ev block */
  short int block;
  short int limit;
  time_t time;
  time_t block_time;
  time_t limit_time;
  /* ev/sec */
  time_t interval;
  long req;
  long req_per_sec;
  int req_per_sec_block_rate;
  int event_req;
} qos_s_entry_t;

typedef struct {
  qos_s_entry_t **ipd;
  qos_s_entry_t **timed;
  int num;
  int max;
  int msize;
} qos_s_t;


static int qoss_comp(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->ip > pB->ip) return 1;
  if(pA->ip < pB->ip) return -1;
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
  int msize = sizeof(qos_s_t) + 
    (sizeof(qos_s_entry_t) * size) + 
    (2 * sizeof(qos_s_entry_t *) * size);
  int i;
  qos_s_t *s = calloc(msize, 1);
  qos_s_entry_t *e = (qos_s_entry_t *)&s[1];
  s->ipd = (qos_s_entry_t **)&e[size];
  s->timed = (qos_s_entry_t **)&s->ipd[size];
  s->num = 0;
  s->max = size;
  s->msize = msize;
  for(i = 0; i < size; i++) {
    s->ipd[i] = e;
    s->timed[i] = e;
    e++;
  }
  return s;
}

static void qoss_free(qos_s_t *s) {
  free(s);
}

/**
 * gets an entry by its ip
 */
static qos_s_entry_t **qoss_get0(qos_s_t *s, qos_s_entry_t *pA) {
  int even = pA->ip % 2;
  if(even) {
    even = s->max / 2;
  }
  return bsearch((const void *)&pA, (const void *)&s->ipd[even], s->max/2, sizeof(qos_s_entry_t *), qoss_comp);
}

static void qoss_sort(qos_s_t *s) {
  qsort(s->timed, s->max/2, sizeof(qos_s_entry_t *), qoss_comp_time);
  qsort(&s->timed[s->max/2], s->max/2, sizeof(qos_s_entry_t *), qoss_comp_time);
}

static void qoss_set(qos_s_t *s, qos_s_entry_t *pA) {
  qos_s_entry_t **pB;
  int even = pA->ip % 2;
  if(even) {
    even = s->max / 2;
  }
  qsort(&s->timed[even], s->max/2, sizeof(qos_s_entry_t *), qoss_comp_time);
  if(s->num < s->max) {
    s->num++;
  }
  pB = &s->timed[even];
  (*pB)->ip = pA->ip;
  (*pB)->time = time(NULL);
  qsort(&s->ipd[even], s->max/2, sizeof(qos_s_entry_t *), qoss_comp);
}

static void qoss_set_fast(qos_s_t *s, qos_s_entry_t *pA, long i) {
  qos_s_entry_t **pB;
  int even = pA->ip % 2;
  if(even) {
    even = s->max / 2;
  }
  if(s->num <= s->max) {
    pB = &s->timed[even + i/2];
    (*pB)->ip = pA->ip;
    (*pB)->time = time(NULL);
    s->num++;
  } else {
    printf("ERROR! no more free slots\n");
    exit(1);
  }
}

static void speed() {
  long size = 50000;
  qos_s_entry_t new;
  qos_s_t *s = qoss_new(size);
  qos_s_entry_t **e = NULL;
  long i;
  struct timeval tv;
  long long start;
  long items[] = { 12, 48333, size-2, size-1000, size/2, size/8, 9827, 25998, 77, 58 };

  printf("> %d %d: %d bytes per client\n", s->msize, s->max, s->msize/s->max);
  new.ip = 0;
  qoss_set(s, &new);
  for(i = 0; i < size; i++) {
    new.ip = i;
    qoss_set_fast(s, &new, i);
  }
  i--;
  printf("added: 0 to %ld\n", i);
  qsort(s->ipd, s->max/2, sizeof(qos_s_entry_t *), qoss_comp);
  qsort(&s->ipd[s->max/2], s->max/2, sizeof(qos_s_entry_t *), qoss_comp);
  qoss_sort(s);
  
  /* get */
  for(i = 0; i < (sizeof(items)/sizeof(long)); i++) {
    new.ip = items[i];
    gettimeofday(&tv, NULL);
    start = tv.tv_sec * 1000000 + tv.tv_usec;
    e = qoss_get0(s, &new);
    gettimeofday(&tv, NULL);
    if(e == NULL) {
      printf("ERROR, %ld not found\n", new.ip);
      exit(1);
    } else {
      printf("get:   %.6lld usec (%ld)\n", (tv.tv_sec * 1000000 + tv.tv_usec) - start, (*e)->ip);
    }
  }

  /* set */
  sleep(1); // those entries are newer
  for(i = 0; i < (sizeof(items)/sizeof(long)); i++) {
    new.ip = items[i]+50000;
    gettimeofday(&tv, NULL);
    start = tv.tv_sec * 1000000 + tv.tv_usec;
    qoss_set(s, &new);
    gettimeofday(&tv, NULL);
    printf("set:   %.6lld usec (%ld)\n", (tv.tv_sec * 1000000 + tv.tv_usec) - start, new.ip);
  }

  for(i = 0; i < (sizeof(items)/sizeof(long)); i++) {
    new.ip = items[i]+50000;
    e = qoss_get0(s, &new);
    if(e == NULL) {
      printf("ERROR, %ld not found\n", new.ip);
      exit(1);
    }
  }

  qoss_free(s);
}

static void func() {
  int size = 12;
  qos_s_entry_t new;
  qos_s_t *s = qoss_new(size);
  qos_s_entry_t **e = NULL;
  int i;
  unsigned long v = 0;
  unsigned long ar[] = { 1, 5, 6, 7, 8, 9, 10, 100 };
  printf("> %d %d: %d bytes per client\n", s->msize, s->max, s->msize/s->max);
  for(i = 0; i < sizeof(ar)/sizeof(unsigned long); i++) {
    new.ip = ar[i];
    e = qoss_get0(s, &new);
    if(!e) {
      printf("[%lu]", new.ip); fflush(stdout);
      sleep(1);
      qoss_set(s, &new);
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
    e = qoss_get0(s, &new);
    if(!e) {
      printf("ERROR-1 pos=%d %lu\n", i, new.ip); fflush(stdout);
      exit(1);
    }
  }
  /* oldest first */
  for(i = 0; i < s->max; i++) {
    e = &s->timed[i];
    printf("pos=%d %lu %lu\n", i, (*e)->ip, (*e)->time);
  }
  /* lowest first */
  v = 0;
  for(i = 0; i < s->max/2; i++) {
    e = &s->ipd[i];
    if((*e)->ip < v) {
      printf("ERROR-2 pos=%d %lu\n", i, (*e)->ip); fflush(stdout);
      exit(1);
    }
    v = (*e)->ip;
  }
  v = 0;
  for(i = s->max/2; i < s->max; i++) {
    e = &s->ipd[i];
    if((*e)->ip < v) {
      printf("ERROR-3 pos=%d %lu\n", i, (*e)->ip); fflush(stdout);
      exit(1);
    }
    v = (*e)->ip;
  }
  qoss_free(s);
}

int main(int argc, char **argv) {
  func();
  speed();
  return 0;
}
