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

static const char revision[] = "$Id: stack.c,v 1.2 2008-03-20 14:28:20 pbuchbinder Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define QS_S_ENTRY_NUM 5

typedef struct {
  unsigned long ip;
  time_t time;
} qos_s_entry_t;

typedef struct {
  qos_s_entry_t **ipd;
  qos_s_entry_t **timed;
  int num;
  int max;
} qos_s_t;

static int qoss_comp(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->ip > pB->ip) return 1;
  if(pA->ip < pB->ip) return -1;
  return 0;
}

static qos_s_t *qoss_new(int size) {
  int i;
  qos_s_entry_t *e = calloc(sizeof(qos_s_entry_t) * size, 1);
  qos_s_t *s = calloc(sizeof(qos_s_t), 1);
  s->ipd = calloc(sizeof(qos_s_entry_t *) * size, 1);
  s->num = 0;
  s->max = size;
  for(i = 0; i < size; i++) {
    s->ipd[i] = e;
    e++;
  }
  return s;
}

/**
 * gets an entry by its ip
 */
static qos_s_entry_t **qoss_get(qos_s_t *s, qos_s_entry_t *pA) {
  return bsearch((const void *)&pA, (const void *)s->ipd, s->max, sizeof(qos_s_entry_t *), qoss_comp);
}

static void qoss_set(qos_s_t *s, qos_s_entry_t *pA) {
  qos_s_entry_t **pB;
  qos_s_entry_t search;
  if(s->num < s->max) {
    search.ip = 0;
    pB = qoss_get(s, &search);
    if(pB) {
      (*pB)->ip = pA->ip;
      s->num++;
      qsort(s->ipd, s->max, sizeof(qos_s_entry_t *), qoss_comp);
      return;
    }
  }
  /* $$$ */
}

int main(int argc, char **argv) {
  qos_s_entry_t search;
  qos_s_entry_t *new = calloc(sizeof(qos_s_entry_t), 1);
  qos_s_t *s = qoss_new(QS_S_ENTRY_NUM);
  qos_s_entry_t **e = NULL;

  new->ip = 888;
  qoss_set(s, new);
  search.ip = 888;
  e = qoss_get(s, &search);
  if(e) {
    printf("%lu\n", (*e)->ip);
  }
  return 0;
}
