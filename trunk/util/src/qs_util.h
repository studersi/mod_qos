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

#ifndef QS_UTIL_H
#define QS_UTIL_H

/* ----------------------------------
 * version info
 * ---------------------------------- */
static const char man_version[] = "11.66";
static const char man_date[] = "May 2020";

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
