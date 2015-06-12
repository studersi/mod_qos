/**
 * Utilities for the quality of service module mod_qos.
 *
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

#ifndef QS_UTIL_H
#define QS_UTIL_H

/* ----------------------------------
 * version info
 * ---------------------------------- */
static const char man_version[] = "11.14";
static const char man_date[] = "June 2015";

/* ----------------------------------
 * definitions
 * ---------------------------------- */
/* huge (128kb) buffer supporting very long lines (twice as
   much as Apache's rotatelogs uses */
#define MAX_LINE_BUFFER 131072
/* smaller buffer, e.g. for qslog */
#define MAX_LINE 32768
#define QS_HUGE_STR 2048
#define CR 13
#define LF 10

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

/* log */
void qs_deleteOldFiles(const char *file_name, int generations);

/* user */
void qs_setuid(const char *username, const char *cmd);

#endif
