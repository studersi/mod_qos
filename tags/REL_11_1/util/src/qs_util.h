/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2014 Pascal Buchbinder
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

#ifndef QS_UTIL_H
#define QS_UTIL_H

/* ----------------------------------
 * version info
 * ---------------------------------- */
static const char man_version[] = "11.1";
static const char man_date[] = "May 2014";

/* ----------------------------------
 * definitions
 * ---------------------------------- */
#define MAX_LINE 32768
#define QS_HUGE_STR 2048
#define CR 13
#define LF 10

/* ----------------------------------
 * structures
 * ---------------------------------- */
typedef struct qs_event_st {
  char       *id;    /**< id, e.g. ip address or client correlator string */
  time_t     time;   /**< last update, used for expiration */
  int        count;  /**< event count/updates */
  struct qs_event_st *next;
} qs_event_t;


/* ----------------------------------
 * functions
 * ---------------------------------- */
char *qs_CMD(const char *cmd);
void qs_man_print(int man, const char *fmt, ...);
void qs_man_println(int man, const char *fmt, ...);

/* io */
int qs_getLine(char *s, int n);
int qs_getLinef(char *s, int n, FILE *f);

/* time */
void qs_time(time_t *tme);
void qs_set2OfflineMode();
void qs_setTime(time_t tme);

/* synchronisation */
void qs_csInitLock();
void qs_csLock();
void qs_csUnLock();

/* events */
void qs_setExpiration(time_t sec);
int  qs_insertEvent(qs_event_t **l_qs_event, char *id);
long qs_countEvent(qs_event_t **l_qs_event);
void qs_deleteEvent(qs_event_t **l_qs_event, char *id);
void qs_GCEvent(qs_event_t **l_qs_event);

/* log */
void qs_deleteOldFiles(const char *file_name, int generations);

#endif
