/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2011 Pascal Buchbinder
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

static const char revision[] = "$Id: qs_util.c,v 1.10 2012-02-09 21:01:38 pbuchbinder Exp $";

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#include "qs_util.h"


/* ----------------------------------
 * global stat counter
 * ---------------------------------- */
static time_t m_qs_expiration = 60 * 10;

/* mutex for counter access */
static pthread_mutex_t m_qs_lock_cs;
/* online/offline mode */
static int m_qs_offline = 0;
/* internal clock for offline analysis
 * stores time in seconds */
static time_t m_qs_virtualSystemTime = 0;

/* ----------------------------------
 * functions
 * ---------------------------------- */

/**
 * man:
 * - escape special chars, like "\" and "-"
 * - wipe leading spaces
 * - wipe tailing LF
 */
void qs_man_print(int man, const char *fmt, ...) {
  char bufin[4096];
  char bufout[4096];
  va_list args;
  int i = 0;
  int j = 0;
  memset(bufin, 0, 4096);
  va_start(args, fmt);
  vsprintf(bufin, fmt, args);
  if(man) {
    // wipe leading spaces
    //    while(bufin[i] == ' ' && bufin[i+1] == ' ') {
    while(bufin[i] == ' ') {
      i++;
    }
  }
  while(bufin[i] && j < 4000) {
    // escape "\\" and "-" for man page
    if(man && (bufin[i] == '\\' || bufin[i] == '-')) {
      bufout[j] = '\\';
      j++;
    }
    if(bufin[i] == '\n') {
      if(man) {
	// skip LF for man page
	i++;
      } else {
	// keep LF
	bufout[j] = bufin[i];
	i++;
	j++;
      }
    } else {
      // standard char
      bufout[j] = bufin[i];
      i++;
      j++;
    }
  }
  bufout[j] = '\0';
  printf("%s", bufout);
  if(man) {
    printf(" ");
  }
}

// escape only
void qs_man_println(int man, const char *fmt, ...) {
  char bufin[4096];
  char bufout[4096];
  va_list args;
  int i = 0;
  int j = 0;
  memset(bufin, 0, 4096);
  va_start(args, fmt);
  vsprintf(bufin, fmt, args);
  while(bufin[i] && j < 4000) {
    // escape "\\" and "-" for man page
    if(man && (bufin[i] == '\\' || bufin[i] == '-')) {
      bufout[j] = '\\';
      j++;
    }
    // standard char
    bufout[j] = bufin[i];
    i++;
    j++;
  }
  bufout[j] = '\0';
  printf("%s", bufout);
}

char *qs_CMD(const char *cmd) {
  char *buf = calloc(1024, 1);
  int i = 0;
  while(cmd[i] && i < 1023) {
    buf[i] = toupper(cmd[i]);
    i++;
  }
  buf[i] = '\0';
  return buf;
}

/* io --------------------------------------------------------- */
/*
 * reads a line from stdin
 */
int qs_getLine(char *s, int n) {
  int i = 0;
  while (1) {
    s[i] = (char)getchar();
    if(s[i] == EOF) return 0;
    if (s[i] == CR) {
      s[i] = getchar();
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
      s[i] = '\0';
      return 1;
    }
    ++i;
  }
}

/*
 * reads a line from file
 */
int qs_getLinef(char *s, int n, FILE *f) {
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

/* time ------------------------------------------------------- */
/*
 * we implement our own time which is either
 * the system time (real time) or the time from
 * the access log lines (offline)
 */
void qs_time(time_t *tme) {
  if(m_qs_offline) {
    /* use virtual time from the access log */
    *tme = m_qs_virtualSystemTime;
  } else {
    time(tme);
  }
}

void qs_set2OfflineMode() {
  m_qs_offline = 1;
}

/* 
 * updates the virtual time
 */
void qs_setTime(time_t tme) {
  m_qs_virtualSystemTime = tme;
}

/* synchronisation -------------------------------------------- */
/*
 * locks all counter
 */
void qs_csLock() {
  pthread_mutex_lock(&m_qs_lock_cs);
}

/*
 * unlocks all counter
 */
void qs_csUnLock() {
  pthread_mutex_unlock(&m_qs_lock_cs);
}


/*
 * init locks
 */
void qs_csInitLock() {
  pthread_mutex_init(&m_qs_lock_cs, NULL);
}

/* events ----------------------------------------------------- */
/*
 * sets the expiration for events
 */
void qs_setExpiration(time_t sec) {
  m_qs_expiration = sec;
}

/*
 * creates a new event entry
 */
qs_event_t *qs_newEvent(char *id) {
  qs_event_t *ev = calloc(sizeof(qs_event_t), 1);
  ev->id = calloc(strlen(id) + 1, 1);
  strcpy(ev->id, id);
  qs_time(&ev->time);
  ev->count = 1;
  return ev;
}

/*
 * deletes an event
 */
void qs_freeEvent(qs_event_t *ev) {
  free(ev->id);
  free(ev);
}

/*
 * inserts an event entry
 * returns event counter (number of updates) for the provided id
 */
int qs_insertEvent(qs_event_t **l_qs_event, char *id) {
  qs_event_t *lp = *l_qs_event;  /** current entry to process */
  qs_event_t *lpl = lp;
  time_t gmt_time;
  qs_time(&gmt_time);
  if(*l_qs_event == NULL) {
    *l_qs_event = qs_newEvent(id);
    return 1;
  }
  while(lp) {
    /* delete expired event */
    if(lp->time < (gmt_time - m_qs_expiration)) {
      qs_event_t *tmp = lp;
      if(lpl == lp) {
	/* first element */
	lpl = lp->next;
	lp = lp->next;
	*l_qs_event = lpl;
      } else {
	lpl->next = lp->next;
	lp = lp->next;
      }
      qs_freeEvent(tmp);
    }
    /* update time of existing event */
    if((lp != NULL) && (strcmp(lp->id, id) == 0)) {
      qs_time(&lp->time);
      lp->count++;
      return lp->count;
    }
    if(lp != NULL) {
      lpl = lp;
      lp = lp->next;
    }
  }
  /* not found, insert new event */
  if(lpl == NULL) {
    /* list has become empty */
    lpl = qs_newEvent(id);
    *l_qs_event = lpl;
  } else {
    lpl->next = qs_newEvent(id);
  }
  return 1;
}

/*
 * deletes the specified event
 */
void qs_deleteEvent(qs_event_t **l_qs_event, char *id) {
  qs_event_t *lp = *l_qs_event;
  qs_event_t *lpl = lp;
  if(*l_qs_event == NULL) {
    return;
  }
  while(lp) {
    if(strcmp(lp->id, id) == 0) {
      qs_event_t *tmp = lp;
      if(lpl == lp) {
	/* first element */
	lpl = lp->next;
	lp = lp->next;
	*l_qs_event = lpl;
      } else {
	lpl->next = lp->next;
	lp = lp->next;
      }
      qs_freeEvent(tmp);
      return;
    }
    if(lp != NULL) {
      lpl = lp;
      lp = lp->next;
    }
  }
}

/*
 * runs garbage collection (deletes expired events)
 */
void qs_GCEvent(qs_event_t **l_qs_event) {
  qs_event_t *lp = *l_qs_event;
  qs_event_t *lpl = lp;
  time_t gmt_time;
  qs_time(&gmt_time);
  if(*l_qs_event == NULL) {
    return;
  }
  while(lp) {
    /* delete expired event */
    if(lp->time < (gmt_time - m_qs_expiration)) {
      qs_event_t *tmp = lp;
      if(lpl == lp) {
	/* first element */
	lpl = lp->next;
	lp = lp->next;
	*l_qs_event = lpl;
      } else {
	lpl->next = lp->next;
	lp = lp->next;
      }
      qs_freeEvent(tmp);
    }
    if(lp != NULL) {
      lpl = lp;
      lp = lp->next;
    }
  }
}

/*
 * get the number of events in the list
 */
long qs_countEvent(qs_event_t **l_qs_event) {
  qs_event_t *lp = *l_qs_event;
  qs_event_t *lpl = lp;
  long count = 0;
  time_t gmt_time;
  qs_time(&gmt_time);
  while(lp) {
    /* delete expired entries */
    if(lp->time < (gmt_time - m_qs_expiration)) {
      qs_event_t *tmp = lp;
      if(lpl == lp) {
	/* first element */
	lpl = lp->next;
	lp = lp->next;
	*l_qs_event = lpl;
      } else {
	lpl->next = lp->next;
	lp = lp->next;
      }
      qs_freeEvent(tmp);
    }
    if(lp != NULL) {
      lpl = lp;
      lp = lp->next;
      count++;
    }
  }
  return count;
}
