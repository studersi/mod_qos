/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://sourceforge.net/projects/mod-qos/ for further
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

static const char revision[] = "$Id: stack.c,v 1.3 2008-03-20 19:38:38 pbuchbinder Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

typedef struct {
  unsigned long ip;
  time_t time;
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
  return bsearch((const void *)&pA, (const void *)s->ipd, s->max, sizeof(qos_s_entry_t *), qoss_comp);
}

static void qoss_set(qos_s_t *s, qos_s_entry_t *pA) {
  qos_s_entry_t **pB;
  if(s->num < s->max) {
    s->num++;
    pB = &s->timed[0];
    (*pB)->ip = pA->ip;
    (*pB)->time = time(NULL);
    qsort(s->ipd, s->max, sizeof(qos_s_entry_t *), qoss_comp);
    qsort(s->timed, s->max, sizeof(qos_s_entry_t *), qoss_comp_time);
  } else {
    pB = &s->timed[0];
    (*pB)->ip = pA->ip;
    (*pB)->time = time(NULL);
    qsort(s->ipd, s->max, sizeof(qos_s_entry_t *), qoss_comp);
    qsort(s->timed, s->max, sizeof(qos_s_entry_t *), qoss_comp_time);
  }
}

static void qoss_set_fast(qos_s_t *s, qos_s_entry_t *pA) {
  qos_s_entry_t **pB;
  if(s->num < s->max) {
    s->num++;
    pB = &s->timed[s->max - s->num];
    (*pB)->ip = pA->ip;
    (*pB)->time = time(NULL);
  }
}

int main(int argc, char **argv) {
  int size = 1000000;
  qos_s_entry_t new;
  qos_s_t *s = qoss_new(size);
  qos_s_entry_t **e = NULL;
  int i;
  int first = 0;
  struct timeval tv;
  long long start;

  printf(">%d %d\n", s->msize, s->max);
  new.ip = 0;
  qoss_set(s, &new);
//  while(s->max > s->num) {
//    new.ip = rand()%(size*10);
//    if(first == 0) {
//      first = new.ip;
//    }
//    e = qoss_get0(s, &new);
//    if(!e) {
//      qoss_set(s, &new);
//    }
//  }
  for(i = 0; i < size; i++) {
    new.ip = i;
    qoss_set_fast(s, &new);
  }
  i++;
  new.ip = i;
  qoss_set(s, &new);
  first = 8725;
//  /* oldest first */
//  for(i = 0; i < s->max; i++) {
//    e = &s->timed[i];
//    printf("%lu %lu\n", (*e)->ip, (*e)->time);
//  }

  /* get */
  printf("\n");
  new.ip = first;
  gettimeofday(&tv, NULL);
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  e = qoss_get0(s, &new);
  gettimeofday(&tv, NULL);
  printf("get: %lld usec\n", (tv.tv_sec * 1000000 + tv.tv_usec) - start);
  /* set */
  new.ip = size;
  gettimeofday(&tv, NULL);
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  qoss_set(s, &new);
  gettimeofday(&tv, NULL);
  printf("set: %lld usec\n", (tv.tv_sec * 1000000 + tv.tv_usec) - start);

  qoss_free(s);
  return 0;
}
