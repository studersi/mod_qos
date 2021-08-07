/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * Utilities for the quality of service module mod_qos.
 *
 * qslog.c: Real time access log data correlation.
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
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <pwd.h>

#include <regex.h>
#include <time.h>

#include <pcre.h>

/* apr */
#include <apr.h>
#include <apr_portable.h>
#include <apr_support.h>
#include <apr_strings.h>

#include "qs_util.h"

/* ----------------------------------
 * definitions
 * ---------------------------------- */
#define ACTIVE_TIME 600 /* how long is a client "active" (ip addresses seen in the log) */
#define LOG_INTERVAL 60 /* log interval ist 60 sec, don't change this value */
#define QS_GC_INTERVAL 10
#define LOG_DET ".detailed"
#define RULE_DELIM ':'
#define MAX_CLIENT_ENTRIES 25000
#define MAX_EVENT_ENTRIES  50000
#define NUM_EVENT_TABLES   8
#define QS_GENERATIONS 14
#define EVENT_DELIM ','
#define QSEVENTPATH "QSEVENTPATH" /* variable name to find event definitions */
#define QSCOUNTERPATH "QSCOUNTERPATH" /* counter rule definitions */
#define COUNTER_PATTERN "([a-zA-Z0-9_]+):([a-zA-Z0-9_]+)[-]([0-9]+)[*]([a-zA-Z0-9_]+)[/]([0-9]+)=([0-9]+)"

/* ----------------------------------
 * structures
 * ---------------------------------- */

typedef struct {
  const char *name;
  int limit;
  int count;
  int total;
  time_t start;
  int duration;
  const char *inc;
  const char *dec;
  int decVal;
} counter_rec_t;

typedef struct {
  unsigned long long lines;
  unsigned long long ms;
  unsigned long long pivot[21];
} duration_t;

typedef struct {
  long request_count;
  long status_1;
  long status_2;
  long status_3;
  long status_4;
  long status_5;
  long long duration_count_ms;
} url_rec_t;

typedef struct {
  long request_count;
  long error_count;
  long long byte_count;
  long long duration;
  long long duration_count_ms;
  long duration_0;
  long duration_1;
  long duration_2;
  long duration_3;
  long duration_4;
  long duration_5;
  long duration_6;
  long status_1;
  long status_2;
  long status_3;
  long status_4;
  long status_5;
  long status_304;
  long connections;
  unsigned long max;
  apr_table_t *events;
  apr_table_t *counters;
  apr_pool_t *pool;
  long get;
  long post;
  long html;
  long img;
  long cssjs;
  long other;
  time_t start_s;
  time_t end_s;
  long firstLine;
  long lastLine;
} client_rec_t;

typedef struct stat_rec_st {
  // id
  char *id;
  regex_t preg;
  struct stat_rec_st *next;

  // counters
  long line_count;
  long long i_byte_count;
  long long byte_count;
  long long duration_count;
  long long duration_count_ms;
  long duration_49;
  long duration_99;
  long duration_499;
  long duration_999;
  long duration_0;
  long duration_1;
  long duration_2;
  long duration_3;
  long duration_4;
  long duration_5;
  long duration_6;
  long connections;

  unsigned long long sum;
  unsigned long long average;
  long average_count;
  unsigned long long averAge;
  long averAge_count;
  unsigned long max;

  duration_t total;

  long status_1;
  long status_2;
  long status_3;
  long status_4;
  long status_5;

  long qos_V;
  long qos_v;
  long qos_s;
  long qos_d;
  long qos_k;
  long qos_t;
  long qos_l;
  long qos_ser;
  long qos_a;
  long qos_u;

  apr_table_t *events;
  apr_pool_t *pool;
} stat_rec_t;

typedef struct qs_event_st {
  char       *id;    /**< id, e.g. ip address or client correlator string */
  time_t     time;   /**< last update, used for expiration */
  long       count;  /**< event count/updates */
} qs_event_t;

/* ----------------------------------
 * global stat counter
 * ---------------------------------- */
static stat_rec_t* m_stat_rec;
static stat_rec_t* m_stat_sub = NULL;

static time_t m_qs_expiration = 60 * 10;

static apr_table_t *m_ip_list[NUM_EVENT_TABLES];   /* IP session store */
static int m_ip_log_max = 0;                       /* already reached store limit */
static apr_table_t *m_user_list[NUM_EVENT_TABLES]; /* user session store */
static int m_usr_log_max = 0;                      /* already reached store limit */
static int m_hasGC = 0;                            /* sep. gc thread or not */
static qs_event_t **m_gc_event_list = NULL;        /* list of entries to delete */

/* output file */
static FILE *m_f = NULL;
static FILE *m_f2 = NULL;
static char  m_file_name[MAX_LINE];
static char  m_file_name2[MAX_LINE];
static int   m_rotate = 0;
static int   m_generations = QS_GENERATIONS;
/* regex to search the time string */
static regex_t m_trx_access;
static regex_t m_trx_j;
static regex_t m_trx_g;
/* real time mode (default) or offline */
static int   m_off = 0;
static int   m_offline = 0;
static int   m_offline_s = 0;
static int   m_offline_data = 0;
static char  m_date_str[MAX_LINE];
static int   m_mem = 0;
static int   m_avms = 0;
static int   m_ct = 0;
static int   m_customcounter = 0;
static apr_table_t *m_client_entries = NULL;
static int   m_max_entries = 0;
static int   m_offline_count = 0;
static apr_table_t *m_url_entries = NULL;
static int   m_offline_url = 0;
static int   m_offline_url_cropped = 0;
static int   m_methods = 0;
/* debug/offline */
static long  m_lines = 0;
static int   m_verbose = 0;
/* enable/disable event counter */
static int   m_hasEV = 0;

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
static qs_event_t *qs_newEvent(const char *id) {
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

/**
 * Defines in which of the NUM_EVENT_TABLES session stores
 * the id shall be added.
 *
 * @param str Session ID to store
 * @return The id of the storage table (0 <= n < NUM_EVENT_TABLES)
 */
static int qs_tableSelector(const char *str) {
  int num = 0;
  int len = strlen(str);
  if(len > 3) {
    if(str[len-1] == '=' ||
       str[len-1] == '\'' ||
       str[len-1] == '"') {
      len--;
    }
  }
  if(str[0] % 2 == 1) {
    num += 1;
  }
  if(len > 1) {
    if(str[len-1] % 2 == 1) {
      num += 2;
    }
    if(len > 2) {
      if(str[len-2] % 2 == 1) {
        num += 4;
      }
    }
  }
  return num;
}

/**
 * Inserts an event entry and deletes expired.
 *
 * @param l_qs_event Pointer to the event list.
 * @param id Identifier, e.g. IP address or user tracking cookie
 * @param type which counter is used (either 'I' or 'U')
 * @return event counter (number of updates) for the provided id
 */
static long qs_insertEventT(apr_table_t **list0, const char *id, const char *type) {
  qs_event_t *lp;
  int select = qs_tableSelector(id);
  apr_table_t *list = list0[select];
  lp = (qs_event_t *)apr_table_get(list, id);
  if(lp) {
    // exists
    qs_time(&lp->time);
    lp->count++;
    return lp->count;
  }
  if(apr_table_elts(list)->nelts >= MAX_EVENT_ENTRIES) {
    if((type[0] == 'I' && m_ip_log_max == 0) ||
       (type[0] == 'U' && m_usr_log_max == 0)) {
      char time_string[1024];
      time_t tm = time(NULL);
      struct tm *ptr = localtime(&tm);
      strftime(time_string, sizeof(time_string), "%a %b %d %H:%M:%S %Y", ptr);
      fprintf(stderr, "[%s] [notice] qslog: reached event (%s) count limit\n",
              time_string, type);
      if(type[0] == 'I') {
        m_ip_log_max = 1;
      }
      if(type[0] == 'U') {
        m_usr_log_max = 1;
      }
    }
    return 0;
  }
  lp = qs_newEvent(id);
  apr_table_setn(list, lp->id, (char *)lp);
  return lp->count;
}

/**
 * deletes expired events
 */
static void gcTable(apr_table_t *list) {
  int max = 0;
  int i;
  apr_table_entry_t *entry;
  time_t gmt_time;
  qs_time(&gmt_time);

  if(m_hasGC) {
    qs_csLock();
  }
  // collect expired events...
  entry = (apr_table_entry_t *) apr_table_elts(list)->elts;
  for(i = 0; i < apr_table_elts(list)->nelts; i++) {
    qs_event_t *lp = (qs_event_t *)entry[i].val;    
    if(lp->time < (gmt_time - m_qs_expiration)) {
      m_gc_event_list[max] = lp;
      max++;
    }
  }
  // ...remove...
  for(i = 0; i < max; i++) {
    if(m_hasGC) {
      /* we don't want to hold a lock for a long time
         => temp release the lock letting the pipe-buffer recover */
      if(i % 10 == 9) {
        qs_csUnLock();
        // wait 1ms
        apr_sleep(1000);
        qs_csLock();
      }
    }
    apr_table_unset(list, m_gc_event_list[i]->id);
  }
  if(m_hasGC) {
    qs_csUnLock();
  }

  // ...and delete them
  for(i = 0; i < max; i++) {
    qs_freeEvent(m_gc_event_list[i]);
  }
}

/**
 * Returns the number of events
 *
 * @param event table
 * @return Number of entries
 */
static long qs_countEventT(apr_table_t **list) {
  int count = 0;
  int t;
  if(!m_hasGC) {
    for(t = 0; t < NUM_EVENT_TABLES; t++) {
      gcTable(list[t]);
    }
  }
  for(t = 0; t < NUM_EVENT_TABLES; t++) {
    count += apr_table_elts(list[t])->nelts;
  }
  return count;
}

/**
 * Calls the event table GC
 */
static void *gcThread(void *argv) {
  int t;
  m_hasGC = 1;
  while(1) {
    sleep(QS_GC_INTERVAL);
    for(t = 0; t < NUM_EVENT_TABLES; t++) {
      gcTable(m_ip_list[t]);
      gcTable(m_user_list[t]);
    }
  }
  return NULL;
}

/* ------------------------------------------------------------ */

/**
 * Helper to print an error message when terminating
 * the program due to an unexpected error.
 */
static void qerror(const char *fmt,...) {
  char buf[MAX_LINE];
  va_list args;
  time_t t = time(NULL);
  char *time_string = ctime(&t);
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  time_string[strlen(time_string) - 1] = '\0';
  fprintf(stderr, "[%s] [error] qslog: %s\n", time_string, buf);
  fflush(stderr);
}

/*
 * Similar to standard strstr() but we ignore case in this version.
 * see server/util.c
 */
static char *qsstrcasestr(const char *s1, const char *s2) {
    char *p1, *p2;
    if (*s2 == '\0') {
        /* an empty s2 */
        return((char *)s1);
    }
    while(1) {
        for ( ; (*s1 != '\0') && (tolower(*s1) != tolower(*s2)); s1++);
        if (*s1 == '\0') {
            return(NULL);
        }
        /* found first character of s2, see if the rest matches */
        p1 = (char *)s1;
        p2 = (char *)s2;
        for (++p1, ++p2; tolower(*p1) == tolower(*p2); ++p1, ++p2) {
            if (*p1 == '\0') {
                /* both strings ended together */
                return((char *)s1);
            }
        }
        if (*p2 == '\0') {
            /* second string ended, a match */
            break;
        }
        /* didn't find a match here, try starting at next character in s1 */
        s1++;
    }
    return((char *)s1);
}

/*
 * skip an element to the next space
 */
static char *skipElement(const char* line) {
  char *p = (char *)line;
  /* check for quotes (double or single) */
  char delim = p[0];
  if(delim == '\'' || delim == '\"') {
    p++;
    // read while we found an '" '" which is not escaped
    while(p[0] != 0 &&
          !(p[0] == delim && p[-1] != '\\' && (p[1] == '\0' || p[1] == ' '))) {
      p++;
    }
    p++;
  } else {
    char *eq = NULL;
    if(m_off) {
      // offline mode: check for <name>='<value>' entry
      eq = strstr(p, "='");
      if(eq && (eq - p) < 10) {
        // near hit
        p = &eq[3];
        while(p[0] != '\'' && p[0] != 0 && p[-1] != '\\') {
          p++;
        }
        p++;
      } else {
        // something else...
        eq=NULL;
      }
    }
    if(!eq) {
      while(p[0] != ' ' && p[0] != 0) {
        p++;
      }
    }
  }
  while(p[0] == ' ') {
    p++;
  }
  return p;
}

/**
 * Cut fp
 */
static void qsNoFloat(char *s) {
  char *pn = strchr(s, '.');
  if(pn) {
    pn[0] = '\0';
  } else {
    pn = strchr(s, ',');
    if(pn) {
      pn[0] = '\0';
    }
  }
}

/**
 * Strip a number.
 */
static void stripNum(char **p) {
  char *s = *p;
  int len;
  while(s && s[0] && (s[0] < '0' || s[0] > '9')) {
    s++;
  }
  len = strlen(s);
  while(len > 0 && (s[len] < '0' || s[len] > '9')) {
    s[len] = '\0';
    len--;
  }
  *p = s;
}

/**
 * Get and cut an element.
 *
 * @param line Line to parse for the next element.
 * @return Pointer to the next element.
 */
static char *cutNext(char **line) {
  char *c = *line;
  char *p = skipElement(*line);
  char delim;
  *line = p;
  if(p[0]) {
    p--; p[0] = '\0';
  }
  /* cut leading and tailing " */
  delim = c[0];
  if(delim == '\'' || delim == '\"') {
    int len;
    c++;
    len = strlen(c);
    while(len > 0 && c[strlen(c)-1] == delim) {
      c[strlen(c)-1] = '\0';
      len--;
    }
  }
  return c;
}

/**
 * Calculates the free system memory. Experimental code.
 * Tested on Solaris (calling vmstat) and Linux (reading
 * from /proc/meminfo).
 *
 * @param buf Buffer to write result to
 * @sz Max. length of the buffer
 */
static void getFreeMem(char *buf, int sz) {
  FILE *f = fopen("/proc/meminfo", "r");
  int mem = 0;
  buf[0] = '\0';
  if(f) {
    char line[MAX_LINE];
    while(!qs_getLinef(line, sizeof(line), f)) {
      if(strncmp(line, "MemFree: ", 9) == 0) {
        char *c = &line[9];
        char *e;
        while(c[0] && ((c[0] == ' ') || (c[0] == '\t'))) c++;
        e = c;
        while(e[0] && (e[0] != ' ')) e++;
        e[0] = '\0';
        mem = mem + atoi(c);
      }
      if(strncmp(line, "Cached: ", 8) == 0) {
        char *c = &line[8];
        char *e;
        while(c[0] && ((c[0] == ' ') || (c[0] == '\t'))) c++;
        e = c;
        while(e[0] && (e[0] != ' ')) e++;
        e[0] = '\0';
        mem = mem + atoi(c);
      }
    }
    fclose(f);
    snprintf(buf, sz, "%d", mem);
  } else {
    // non linux
//#ifdef _SC_AVPHYS_PAGES
//    long pageSize = sysconf(_SC_PAGESIZE);
//    long freePages = sysconf(_SC_AVPHYS_PAGES);
//    mem = pageSize * freePages / 1024;
//    snprintf(buf, sz, "%d", mem);
//#else
    /* fallback using vmstat (experimental code) */
    char vmstat[] = "/usr/bin/vmstat";
    struct stat attr;
    if(stat(vmstat, &attr) == 0) {
      char command[1024];
      char outfile[1024];
      snprintf(outfile, sizeof(outfile), "/tmp/qslog.%d", getpid());
      snprintf(command, sizeof(command), "%s 1 2 1>%s", vmstat, outfile);
      system(command);
      f = fopen(outfile, "r");
      if(f) {
        char line[MAX_LINE];
        int i = 1;
        while(!qs_getLinef(line, sizeof(line), f)) {
          if(i == 4) {
            // free memory only (ignores cache)
            int j = 0;
            char *p = line;
            while(p && j < 4) {
              p++;
              p = strchr(p, ' ');
              j++;
            }
            if(p && (j == 4)) {
              char *e;
              p++;
              e = strchr(p, ' ');
              if(e) {
                e[0] = '\0';
                snprintf(buf, sz, "%s", p);
              }
            }
            break;
          }
          i++;
        }
        fclose(f);
        unlink(outfile);
      }
    }
//#endif
  }
}

/* value names in csv output */
#define NRS "r/s"
#define NBS "b/s"
#define NBIS "ib/s"
#define NAV "av"
#define NAVMS "avms"

/**
 * Writes the statistic entry stat_rec to the file.
 *
 * @param f File to write to
 * @param timeStr Time string (prefix)
 * @param stat_rec Data to write
 * @offline Offline mode (less data, e.g. no load)
 * @param main Indicates if it is the main log or a sub entry for the detailed log
 * @param av Load
 * @param mem Free memory
 */
static void printStat2File(FILE *f, char *timeStr, stat_rec_t *stat_rec,
                           int offline, int main,
                           double *av, const char *mem) {
  char bis[256];
  char esco[256];
  char ip[256];
  char usr[256];
  char avms[256];
  char custom[256];
  bis[0] = '\0';
  esco[0] = '\0';
  avms[0] = '\0';
  custom[0] = '\0';

  m_ip_log_max = 0;
  m_usr_log_max = 0;

  if(stat_rec->i_byte_count != -1) {
    sprintf(bis, NBIS";%lld;", stat_rec->i_byte_count/LOG_INTERVAL);
  }
  if(main && stat_rec->connections != -1) {
    sprintf(esco, "esco;%ld;", stat_rec->connections);
  }
  if(m_avms) {
    sprintf(avms, NAVMS";%lld;",
            stat_rec->duration_count_ms/(stat_rec->line_count == 0 ? 1 : stat_rec->line_count));
    // improve accuracy (rounding errors):
    stat_rec->duration_count = stat_rec->duration_count_ms / 1000;
  }
  if(m_customcounter) {
    // max len: 18446744073709551615
    sprintf(custom, "s;%llu;a;%llu;A;%llu;M;%lu;",
            stat_rec->sum,
            stat_rec->average / (stat_rec->average_count == 0 ? 1 : stat_rec->average_count),
            stat_rec->averAge / (stat_rec->averAge_count == 0 ? 1 : stat_rec->averAge_count),
            stat_rec->max);
  }
  if(main) {
    sprintf(ip, "ip;%ld;", qs_countEventT(m_ip_list));
    sprintf(usr, "usr;%ld;", qs_countEventT(m_user_list));
  } else {
    ip[0] = '\0';
    usr[0] = '\0';
  }

  fprintf(f, "%s;"
          "%s"
          NRS";%ld;"
          "req;%ld;"
          NBS";%lld;"
          "%s"
          "%s"
          "1xx;%ld;"
          "2xx;%ld;"
          "3xx;%ld;"
          "4xx;%ld;"
          "5xx;%ld;"
          "%s"
          NAV";%lld;",
          timeStr,
          main ? "" : stat_rec->id,
          stat_rec->line_count/LOG_INTERVAL,
          stat_rec->line_count,
          stat_rec->byte_count/LOG_INTERVAL,
          bis,
          esco,
          stat_rec->status_1,
          stat_rec->status_2,
          stat_rec->status_3,
          stat_rec->status_4,
          stat_rec->status_5,
          avms,
          stat_rec->duration_count/(stat_rec->line_count == 0 ? 1 : stat_rec->line_count));
  if(m_avms) {
    fprintf(f,
            "0-49ms;%ld;"
            "50-99ms;%ld;"
            "100-499ms;%ld;"
            "500-999ms;%ld;",
            stat_rec->duration_49,
            stat_rec->duration_99,
            stat_rec->duration_499,
            stat_rec->duration_999);
  }
  fprintf(f,
          "<1s;%ld;"
          "1s;%ld;"
          "2s;%ld;"
          "3s;%ld;"
          "4s;%ld;"
          "5s;%ld;"
          ">5s;%ld;"
          "%s"
          "%s"
          ,
          stat_rec->duration_0,
          stat_rec->duration_1,
          stat_rec->duration_2,
          stat_rec->duration_3,
          stat_rec->duration_4,
          stat_rec->duration_5,
          stat_rec->duration_6,
          ip,
          usr
          );
  if(m_hasEV) {
    fprintf(f,
            "qV;%ld;"
            "qv;%ld;"
            "qS;%ld;"
            "qD;%ld;"
            "qK;%ld;"
            "qT;%ld;"
            "qL;%ld;"
            "qs;%ld;"
            "qA;%ld;"
            "qu;%ld;",
            stat_rec->qos_V,
            stat_rec->qos_v,
            stat_rec->qos_s,
            stat_rec->qos_d,
            stat_rec->qos_k,
            stat_rec->qos_t,
            stat_rec->qos_l,
            stat_rec->qos_ser,
            stat_rec->qos_a,
            stat_rec->qos_u);
  }
  fprintf(f, "%s",
          custom);
  stat_rec->line_count = 0;
  stat_rec->byte_count = 0;
  if(stat_rec->i_byte_count != -1) {
    stat_rec->i_byte_count = 0;
  }
  if(main && (stat_rec->connections != -1)) {
    stat_rec->connections = 0;
  }
  stat_rec->sum = 0;
  stat_rec->average = 0;
  stat_rec->average_count = 0;
  stat_rec->averAge = 0;
  stat_rec->averAge_count = 0;
  stat_rec->max = 0;
  stat_rec->status_1 = 0;
  stat_rec->status_2 = 0;
  stat_rec->status_3 = 0;
  stat_rec->status_4 = 0;
  stat_rec->status_5 = 0;
  stat_rec->duration_count = 0;
  stat_rec->duration_count_ms = 0;
  stat_rec->duration_49 = 0;
  stat_rec->duration_99 = 0;
  stat_rec->duration_499 = 0;
  stat_rec->duration_999 = 0;
  stat_rec->duration_0 = 0;
  stat_rec->duration_1 = 0;
  stat_rec->duration_2 = 0;
  stat_rec->duration_3 = 0;
  stat_rec->duration_4 = 0;
  stat_rec->duration_5 = 0;
  stat_rec->duration_6 = 0;
  stat_rec->qos_V = 0;
  stat_rec->qos_v = 0;
  stat_rec->qos_s = 0;
  stat_rec->qos_d = 0;
  stat_rec->qos_k = 0;
  stat_rec->qos_t = 0;
  stat_rec->qos_l = 0;
  stat_rec->qos_ser = 0;
  stat_rec->qos_a = 0;
  stat_rec->qos_u = 0;
  if(main) {
    if(!offline) {
      fprintf(f, "sl;%.2f;", av[0]);
      if(m_mem) {
        fprintf(f, "m;%s;", mem[0] ? mem : "-");
      }
    } else {
      m_offline_data = 0;
    }
  }
  if(apr_table_elts(stat_rec->events)->nelts > 0) {
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *) apr_table_elts(stat_rec->events)->elts;
    for(i = 0; i < apr_table_elts(stat_rec->events)->nelts; i++) {
      const char *eventName = entry[i].key;
      int *eventVal = (int *)entry[i].val;
      fprintf(f, "%s;%d;", eventName, *eventVal);
      (*eventVal) = 0;
    }
  }
  fprintf(f, "\n");
}

/**
 * updates the counter by event or status conditions
 */
static void qs_updateCounter(apr_pool_t *pool, char *E, char *S, apr_table_t *counters) {
  time_t ltime;
  apr_table_entry_t *entry;
  int i;
  if(counters == NULL) {
    return;
  }
  if(S == 0 && E == NULL) {
    return;
  }
  qs_time(&ltime);
  entry = (apr_table_entry_t *) apr_table_elts(counters)->elts;
  for(i = 0; i < apr_table_elts(counters)->nelts; i++) {
    counter_rec_t *c = (counter_rec_t *)entry[i].val;
    if(c->start && ((c->start + c->duration) < ltime)) {
      // expired
      c->start = 0;
      c->count = 0;
    }
  }
  for(i = 0; i < apr_table_elts(counters)->nelts; i++) {
    counter_rec_t *c = (counter_rec_t *)entry[i].val;
    if(S) {
      if((strncmp(c->name, "STATUS", 6) == 0) &&
         (strstr(c->inc, S) != NULL)) {
        if(c->start == 0) {
          c->start = ltime;
        }
        c->count++;
        if(c->count == c->limit) {
          c->total++;
        }
      }
    }
    if(E) {
      if(strstr(c->inc, E)) {
        if(c->start == 0) {
          c->start = ltime;
        }
        c->count++;
        if(strstr(c->dec, E)) {
          if(c->count > c->decVal) {
            c->count = c->count - c->decVal;
          } else {
            c->count = 0;
          }
        }
        if(c->count == c->limit) {
          c->total++;
        }
      }
    }
  }
}

static void qs_updateEvents(apr_pool_t *pool, char *E, apr_table_t *events) {
  if(!E[0]) {
    return;
  }
  while(E) {
    char *restore = NULL;
    char *sep = strchr(E, EVENT_DELIM);
    int *val;
    if(sep) {
      sep[0] = '\0';
      restore = sep;
      sep++;
    }
    if(isalnum(E[0])) {
      val = (int *)apr_table_get(events, E);
      if(val) {
        (*val)++;
      } else {
        // new event
        char *name = apr_pstrdup(pool, E);
        val = apr_pcalloc(pool, sizeof(int));
        (*val) = 1;
        apr_table_setn(events, name, (char *)val);
      }
    }
    E = sep;
    if(restore) {
      // supports multiple parsing of the event string
      restore[0] = EVENT_DELIM;
    }
  }
}

/**
 * Reads the counter rule file, each line contains:
 * <name>:<event>-<n>*<event>/<duration>=<limit>
 */
static void qsInitCounter(apr_pool_t *pool, apr_table_t *counters) {
  const char *envFile = getenv(QSCOUNTERPATH);
  if(envFile != NULL) {
    const char *errptr = NULL;
    int erroffset;
    int ovector[100];
    pcre *pcrestat = pcre_compile(COUNTER_PATTERN, PCRE_CASELESS, &errptr, &erroffset, NULL);
    FILE *file = fopen(envFile, "r"); 
    if(file != NULL) {
      char line[MAX_LINE];
      while(!qs_getLinef(line, sizeof(line), file)) {
        if(pcre_exec(pcrestat, NULL, line, strlen(line), 0, 0, ovector, 100) >= 0) {
          counter_rec_t *c = apr_pcalloc(pool, sizeof(counter_rec_t));
          line[ovector[2] + ovector[3] - ovector[2]] = '\0';
          line[ovector[4] + ovector[5] - ovector[4]] = '\0';
          line[ovector[6] + ovector[7] - ovector[6]] = '\0';
          line[ovector[8] + ovector[9] - ovector[8]] = '\0';
          line[ovector[10] + ovector[11] - ovector[10]] = '\0';
 
          c->name = apr_pstrdup(pool, &line[ovector[2]]);
          c->count = 0;
          c->total = 0;
          c->start = 0;
          c->inc = apr_pstrdup(pool, &line[ovector[4]]);
          c->decVal = atoi(&line[ovector[6]]);
          c->dec = apr_pstrdup(pool, &line[ovector[8]]);
          c->duration = atoi(&line[ovector[10]]);
          c->limit = atoi(&line[ovector[12]]);
          if(m_verbose) {
            fprintf(stderr, "%s : %s - (%d * %s) / %d = %d\n",
                    c->name, c->inc, c->decVal, c->dec, c->duration, c->limit);
          }
          apr_table_setn(counters, c->name, (char *)c);
        }
      }
      fclose(file);
    }
  }
}

/**
 * Initializes the event table by the events specified within the
 * file whose path is defined by the QSEVENTPATH environment
 * variable.
 * File contains event names, separated by comma and/or new line.
 *
 * @param pool To allocate memory
 * @param events Table to init
 */
static void qsInitEvent(apr_pool_t *pool, apr_table_t *events) {
  const char *envFile = getenv(QSEVENTPATH);
  if(envFile != NULL) {
    FILE *file = fopen(envFile, "r"); 
    if(file != NULL) {
      char line[MAX_LINE];
      while(!qs_getLinef(line, sizeof(line), file)) {
        char *p = line;
        char *name;
        int *val;
        while(p && p[0]) {
          /* file contains a list of known events (comma sep.
             event names on one or multiple lines) */
          char *n = strchr(p, EVENT_DELIM);
          if(n) {
            n[0] = '\0';
            n++;
          }
          name = apr_pstrdup(pool, p);
          val = apr_pcalloc(pool, sizeof(int));
          (*val) = 0;
          apr_table_setn(events, name, (char *)val);
          p = n;
        }
      }
      fclose(file);
    }
  }
}

/**
 * Creates and init new status rec
 *
 * @param id Identification of the id
 * @param pattern Pattern to match the log data line
 * @return
 */
static stat_rec_t *createRec(apr_pool_t *pool, const char *id, const char *pattern) {
  stat_rec_t *rec = calloc(sizeof(stat_rec_t), 1);
  rec->id = calloc(strlen(id)+2, 1);
  sprintf(rec->id, "%s;", id);
  rec->id[strlen(id)+1] = '\0';
  if(regcomp(&rec->preg, pattern, REG_EXTENDED)) {
    qerror("failed to compile pattern %s", pattern);
    exit(1);
  }
  rec->next = NULL;

  rec->line_count = 0;
  rec->i_byte_count = -1;
  rec->byte_count = 0;
  rec->duration_count = 0;
  rec->duration_count_ms = 0;
  rec->duration_49 = 0;
  rec->duration_99 = 0;
  rec->duration_499 = 0;
  rec->duration_999 = 0;
  rec->duration_0 = 0;
  rec->duration_1 = 0;
  rec->duration_2 = 0;
  rec->duration_3 = 0;
  rec->duration_4 = 0;
  rec->duration_5 = 0;
  rec->duration_6 = 0;
  rec->connections = -1;

  rec->sum = 0;
  rec->average = 0;
  rec->average_count = 0;
  rec->averAge = 0;
  rec->averAge_count = 0;
  rec->max = 0;

  rec->total.lines = 0;
  rec->total.ms = 0;
  {
    int p = 0;
    for(p = 0; p < 21; p++) {
      rec->total.pivot[p] = 0;
    }
  }
  
  rec->status_1 = 0;
  rec->status_2 = 0;
  rec->status_3 = 0;
  rec->status_4 = 0;
  rec->status_5 = 0;

  rec->qos_V = 0;
  rec->qos_v = 0;
  rec->qos_s = 0;
  rec->qos_d = 0;
  rec->qos_k = 0;
  rec->qos_t = 0;
  rec->qos_l = 0;
  rec->qos_ser = 0;
  rec->qos_a = 0;
  rec->qos_u = 0;

  rec->events = apr_table_make(pool, 300);
  rec->pool = pool;
  qsInitEvent(pool, rec->events);
  return rec;
}

/**
 * Retrieves the best matching record (longest match(
 * 
 * @param Parameter to match, e.g. URL
 * @return Matching entry (NULL if no match)
 */
static stat_rec_t *getRec(const char *value) {
  regmatch_t ma[1];
  int len = 0;
  stat_rec_t *r = m_stat_sub;
  stat_rec_t *rec = NULL;
  while(r) {
    if(regexec(&r->preg, value, 1, ma, 0) == 0) {
      int l = ma[0].rm_eo - ma[0].rm_so + 1;
      if(l > len) {
        // longest match
        len = l;
        rec = r;
      }
    }
    r = r->next;
  }
  return rec;
}

/**
 * writes all stat data to the out file
 * an resets all counters.
 *
 * @param timeStr
 */
static void printAndResetStat(char *timeStr) {
  stat_rec_t *r = m_stat_sub;
  double av[1];
  char mem[256];
  if(!m_offline) {
    getloadavg(av, 1);
    if(m_mem) {
      getFreeMem(mem, sizeof(mem));
    } else {
      mem[0] = '\0';
    }
  } else {
    mem[0] = '\0';
  }
  qs_csLock();
  printStat2File(m_f, timeStr, m_stat_rec, m_offline, 1, av, mem);
  while(r) {
    printStat2File(m_f2, timeStr, r, m_offline, 0, av, mem);
    r = r->next;
  }
  qs_csUnLock();
  fflush(m_f);
  if(m_f2) {
    fflush(m_f2);
  }
}

/**
 * Updates the per url records
 */
static void updateUrl(apr_pool_t *pool, char *R, char *S, long tmems) {
  url_rec_t *url_rec;
  char *marker;
  if(R == NULL) {
    return;
  }
  if(!isalpha(R[0])) {
    fprintf(stdout, "A(%ld)", m_lines);
    return;
  }
  marker = strchr(R, ' ');
  if(marker == NULL) {
    fprintf(stdout, "E(%ld)", m_lines);
    return;
  }
  marker[0] = ';';
  marker = strrchr(R, ' ');
  if(marker) {
    marker[0] = '\0';
  }
  marker = strchr(R, '?');
  if(marker) {
    marker[0] = '\0';
  }
  if(m_offline_url_cropped) {
    char *root = strchr(R, '/');
    marker = strrchr(R, '/');
    if(marker && marker != root) {
      marker[0] = '\0';
    }
  }
  url_rec = (url_rec_t *)apr_table_get(m_url_entries, R);
  if(url_rec == NULL) {
    if(apr_table_elts(m_url_entries)->nelts >= MAX_CLIENT_ENTRIES) {
      // limitation
      if(!m_max_entries) {
        fprintf(stderr, "\nreached max url entries (%d)\n", MAX_CLIENT_ENTRIES);
        m_max_entries = 1;
      }
      return;
    }
    url_rec = apr_pcalloc(pool, sizeof(url_rec_t));
    url_rec->request_count = 0;
    url_rec->status_1 = 0;
    url_rec->status_2 = 0;
    url_rec->status_3 = 0;
    url_rec->status_4 = 0;
    url_rec->status_5 = 0;
    url_rec->duration_count_ms = 0;
    apr_table_setn(m_url_entries, apr_pstrdup(pool, R), (char *)url_rec);
  }
  url_rec->request_count++;
  if(S) {
    if(S[0] == '1') {
      url_rec->status_1++;
    } else if(S[0] == '1') {
      url_rec->status_1++;
    } else if(S[0] == '2') {
      url_rec->status_2++;
    } else if(S[0] == '3') {
      url_rec->status_3++;
    } else if(S[0] == '4') {
      url_rec->status_4++;
    } else if(S[0] == '5') {
      url_rec->status_5++;
    }
  }
  url_rec->duration_count_ms += tmems;
}

/**
 * Updates the per client record
 */
static void updateClient(apr_pool_t *pool, char *T, char *t, char *D, char *S,
                         char *BI, char *B, char *R, char *I, char *U, char *Q,
                         char *E, char *k, char *C, char *M, char *ct, long tme, long tmems,
                         char *m) {
  client_rec_t *client_rec;
  const char *id = I; // ip
  if(id == NULL) {
    id = U; // user
  }
  if(id == NULL) {
    return;
  }
  client_rec = (client_rec_t *)apr_table_get(m_client_entries, id);
  if(client_rec == NULL) {
    char *tid;
    if(apr_table_elts(m_client_entries)->nelts >= MAX_CLIENT_ENTRIES) {
      // limitation: speed (table to big) and memory
      if(!m_max_entries) {
        fprintf(stderr, "\nreached max client entries (%d)\n", MAX_CLIENT_ENTRIES);
        m_max_entries = 1;
      }
      return;
    }
    tid = calloc(strlen(id)+1, 1);
    client_rec = calloc(sizeof(client_rec_t), 1);
    strcpy(tid, id);
    tid[strlen(id)] = '\0';
    client_rec->request_count = 0;
    client_rec->error_count = 0;
    client_rec->byte_count = 0;
    client_rec->duration = 0;
    client_rec->duration_count_ms = 0;
    client_rec->duration_0 = 0;
    client_rec->duration_1 = 0;
    client_rec->duration_2 = 0;
    client_rec->duration_3 = 0;
    client_rec->duration_4 = 0;
    client_rec->duration_5 = 0;
    client_rec->duration_6 = 0;
    client_rec->status_1 = 0;
    client_rec->status_2 = 0;
    client_rec->status_3 = 0;
    client_rec->status_4 = 0;
    client_rec->status_5 = 0;
    client_rec->status_304 = 0;
    client_rec->connections = 0;
    client_rec->max = 0;
    client_rec->events = apr_table_make(pool, 100);
    client_rec->counters = apr_table_make(pool, 10);
    client_rec->pool = pool;
    client_rec->get = 0;
    client_rec->post = 0;
    client_rec->html = 0;
    client_rec->img = 0;
    client_rec->cssjs = 0;
    client_rec->other = 0;
    qs_time(&client_rec->start_s);
    client_rec->end_s = client_rec->start_s + 1; // +1 prevents div by 0
    client_rec->firstLine = m_lines;
    qsInitEvent(pool, client_rec->events);
    qsInitCounter(pool, client_rec->counters);
    apr_table_setn(m_client_entries, tid, (char *)client_rec);
  } else {
    qs_time(&client_rec->end_s);
  }
  client_rec->lastLine = m_lines;
  client_rec->request_count++;
  client_rec->duration += tme;
  client_rec->duration_count_ms += tmems;
  if(k != NULL) {
    if(k[0] == '0' && k[1] == '\0') {
      client_rec->connections++;
    }
  }
  if(tme < 1) {
    client_rec->duration_0++;
  } else if(tme == 1) {
    client_rec->duration_1++;
  } else if(tme == 2) {
    client_rec->duration_2++;
  } else if(tme == 3) {
    client_rec->duration_3++;
  } else if(tme == 4) {
    client_rec->duration_4++;
  } else if(tme == 5) {
    client_rec->duration_5++;
  } else {
    client_rec->duration_6++;
  }
  if(B != NULL) {
    client_rec->byte_count += atol(B);
  }
  if(ct) {
    if(qsstrcasestr(ct, "html")) {
      client_rec->html++;
    } else if(qsstrcasestr(ct, "image")) {
      client_rec->img++;
    } else if(qsstrcasestr(ct, "css")) {
      client_rec->cssjs++;
    } else if(qsstrcasestr(ct, "javascript")) {
      client_rec->cssjs++;
    } else {
      client_rec->other++;
    }
  }
  if(M && M[0]) {
    long max = atol(M);
    if(max > client_rec->max) {
      client_rec->max = max;
    }
  }
  if(m) {
    if(strcasecmp(m, "get") == 0) {
      client_rec->get++;
    } else if(strcasecmp(m, "post") == 0) {
      client_rec->post++;
    }
  }
  if(S != NULL) {
    if(strcmp(S, "200") != 0 && strcmp(S, "304") != 0 && strcmp(S, "302") != 0) {
      client_rec->error_count++;
    }
    if(S[0] == '1') {
      client_rec->status_1++;
    } else if(S[0] == '1') {
      client_rec->status_1++;
    } else if(S[0] == '2') {
      client_rec->status_2++;
    } else if(S[0] == '3') {
      client_rec->status_3++;
      if(S[1] == '0' && S[2] == '4') {
        client_rec->status_304++;
      }
    } else if(S[0] == '4') {
      client_rec->status_4++;
    } else if(S[0] == '5') {
      client_rec->status_5++;
    }
  }
  if(E != NULL) {
    qs_updateEvents(client_rec->pool, E, client_rec->events);
  }
  qs_updateCounter(client_rec->pool, E, S, client_rec->counters);
  return;
}

/**
 * Updates standard record
 */
static void updateRec(stat_rec_t *rec, char *T, char *t, char *D, char *S,
                      char *s, char *a, char *A,
                      char *BI, char *B, char *R, char *I, char *U, char *Q,
                      char *E, char *k, char *C, char *M, long tme, long tmems) {
  if(Q != NULL) {
    if(strchr(Q, 'V') != NULL) {
      rec->qos_V++;
    }
    if(strchr(Q, 'v') != NULL) {
      rec->qos_v++;
    }
    if(strchr(Q, 'S') != NULL) {
      rec->qos_s++;
    }
    if(strchr(Q, 'D') != NULL) {
      rec->qos_d++;
    }
    if(strchr(Q, 'K') != NULL) {
      rec->qos_k++;
    }
    if(strchr(Q, 'T') != NULL) {
      rec->qos_t++;
    }
    if(strchr(Q, 'L') != NULL) {
      rec->qos_l++;
    }
    if(strchr(Q, 's') != NULL) {
      rec->qos_ser++;
    }
    if(strchr(Q, 'A') != NULL) {
      rec->qos_a++;
    }
    if(strchr(Q, 'u') != NULL) {
      rec->qos_u++;
    }
  }
  if(E != NULL) {
    qs_updateEvents(rec->pool, E, rec->events);
  }
  if(I != NULL) {
    /* update/store client IP */
    qs_insertEventT(m_ip_list, I, "I");
  }
  if(U != NULL) {
    /* update/store user */
    qs_insertEventT(m_user_list, U, "U");
  }
  if(B != NULL) {
    /* transferred bytes */
    rec->byte_count += atoi(B);
  }
  if(BI != NULL) {
    /* transferred bytes */
    rec->i_byte_count += atoi(BI);
  }
  if(k != NULL) {
    if(k[0] == '0' && k[1] == '\0') {
      rec->connections++;
    }
  }
  if(s != NULL) {
    rec->sum += atol(s);
  }
  if(a != NULL && a[0]) {
    rec->average += atol(a);
    rec->average_count++;
  }
  if(A != NULL && A[0]) {
    rec->averAge += atol(A);
    rec->averAge_count++;
  }
  if(M && M[0]) {
    long max = atol(M);
    if(max > rec->max) {
      rec->max = max;
    }
  }

  if(S != NULL) {
    if(S[0] == '1') {
      rec->status_1++;
    } else if(S[0] == '1') {
      rec->status_1++;
    } else if(S[0] == '2') {
      rec->status_2++;
    } else if(S[0] == '3') {
      rec->status_3++;
    } else if(S[0] == '4') {
      rec->status_4++;
    } else if(S[0] == '5') {
      rec->status_5++;
    } 
  }
  if(T != NULL || t != NULL || D != NULL) {
    /* response duration */
    rec->duration_count += tme;
    rec->duration_count_ms += tmems;
    if(m_offline_s) {
      long min = 0;
      long max = 50;
      int p;
      rec->total.lines++;
      rec->total.ms += tmems;
      for(p = 0; p < 20; p++) {
        // 0ms <= time < 50ms etc.
        if((min <= tmems) && (tmems < max)) {
          rec->total.pivot[p]++;
          break;
        }
        min = max;
        max += 50;
      }
      if(tmems >= 1000) {
        // time >= 1000ms (20x50ms)
        rec->total.pivot[20]++;
      }
    }
    if(m_avms) {
      if(tmems < 49) {
        rec->duration_49++;
      } else if(50 <= tmems && tmems < 99) {
        rec->duration_99++;
      } else if(100 <= tmems && tmems < 499) {
        rec->duration_499++;
      } else if(500 <= tmems && tmems < 999) {
        rec->duration_999++;
      }
    }
    if(tme < 1) {
      rec->duration_0++;
    } else if(tme == 1) {
      rec->duration_1++;
    } else if(tme == 2) {
      rec->duration_2++;
    } else if(tme == 3) {
      rec->duration_3++;
    } else if(tme == 4) {
      rec->duration_4++;
    } else if(tme == 5) {
      rec->duration_5++;
    } else {
      rec->duration_6++;
    }
  }
  /* request counter */
  rec->line_count++;
}

/*
 * updates the counters based on the information
 * found in the current access log line
 *
 * . = any string to skip till the next [space]
 * T = duration
 * B = bytes
 *
 * Example:
 * 127.0.0.1 [03/Nov/2006:21:06:41 +0100] "GET /index.html HTTP/1.1" 200 2836 "Wget/1.9.1" 0
 * .         .                     .      R                                   .            T
 */
static void updateStat(apr_pool_t *pool, const char *cstr, char *line) {
  stat_rec_t *rec = NULL;
  char *T = NULL; /* time */
  char *t = NULL; /* time ms */
  char *D = NULL; /* time us */
  char *S = NULL; /* status */
  char *BI = NULL; /* bytes in */
  char *B = NULL; /* bytes */
  char *R = NULL; /* request line */
  char *I = NULL; /* client ip */
  char *U = NULL; /* user */
  char *Q = NULL; /* mod_qos event message */
  char *k = NULL; /* connections (keep alive requests = 0) */
  char *C = NULL; /* custom patter matching the config file */
  char *s = NULL; /* sum */
  char *a = NULL; /* average 1 */
  char *A = NULL; /* average 2 */
  char *M = NULL; /* max */
  char *E = NULL; /* events */
  char *ct = NULL; /* content type */
  char *m = NULL; /* method */
  const char *c = cstr;
  char *l = line;
  long tme;
  long tmems;
  if(!line[0]) return;
  if(m_off) {
    m_lines++;
  }
  while(c[0]) {
    /* process known types */
    if(c[0] == '.') {
      if(l != NULL && l[0] != '\0') {
        l = skipElement(l);
      }
    } else if(c[0] == 'T') {
      if(l != NULL && l[0] != '\0') {
        T = cutNext(&l);
      }
    } else if(c[0] == 't') {
      if(l != NULL && l[0] != '\0') {
        t = cutNext(&l);
      }
    } else if(c[0] == 'D') {
      if(l != NULL && l[0] != '\0') {
        D = cutNext(&l);
      }
    } else if(c[0] == 'S') {
      if(l != NULL && l[0] != '\0') {
        S = cutNext(&l);
      }
    } else if(c[0] == 'B') {
      if(l != NULL && l[0] != '\0') {
        B = cutNext(&l);
      }
    } else if(c[0] == 'i') {
      if(l != NULL && l[0] != '\0') {
        BI = cutNext(&l);
      }
    } else if(c[0] == 'k') {
      if(l != NULL && l[0] != '\0') {
        k = cutNext(&l);
      }
    } else if(c[0] == 'C') {
      if(l != NULL && l[0] != '\0') {
        C = cutNext(&l);
      }
    } else if(c[0] == 'c') {
      if(l != NULL && l[0] != '\0') {
        ct = cutNext(&l);
      }
    } else if(c[0] == 'm') {
      if(l != NULL && l[0] != '\0') {
        m = cutNext(&l);
      }
    } else if(c[0] == 'R') {
      if(l != NULL && l[0] != '\0') {
        R = cutNext(&l);
      }
    } else if(c[0] == 'I') {
      if(l != NULL && l[0] != '\0') {
        I = cutNext(&l);
      }
    } else if(c[0] == 'U') {
      if(l != NULL && l[0] != '\0') {
        U = cutNext(&l);
      }
    } else if(c[0] == 'Q') {
      if(l != NULL && l[0] != '\0') {
        Q = cutNext(&l);
      }
    } else if(c[0] == 's') {
      if(l != NULL && l[0] != '\0') {
        s = cutNext(&l);
      }
    } else if(c[0] == 'a') {
      if(l != NULL && l[0] != '\0') {
        a = cutNext(&l);
      }
    } else if(c[0] == 'A') {
      if(l != NULL && l[0] != '\0') {
        A = cutNext(&l);
      }
    } else if(c[0] == 'M') {
      if(l != NULL && l[0] != '\0') {
        M = cutNext(&l);
      }
    } else if(c[0] == 'E') {
      if(l != NULL && l[0] != '\0') {
        E = cutNext(&l);
      }
    } else if(c[0] == ' ') {
      /* do nothing */
    } else {
      /* undefined/unknown char, skip it */
      if(l != NULL && l[0] != '\0') {
        l++;
      }
    }
    c++;
  }
  if(C) {
    rec = getRec(C);
  }

  qs_csLock();
  if(B != NULL) {
    /* transferred bytes */
    stripNum(&B);
  }
  if(BI != NULL) {
    /* transferred bytes */
    stripNum(&BI);
  }
  if(k != NULL) {
    stripNum(&k);
  }
  if(S != NULL) {
    stripNum(&S);
  }
  if(s != NULL) {
    stripNum(&s);
    qsNoFloat(s);
  }
  if(a != NULL) {
    stripNum(&a);
    qsNoFloat(a);
  }
  if(A != NULL) {
    stripNum(&A);
    qsNoFloat(A);
  }
  if(M != NULL) {
    stripNum(&M);
    qsNoFloat(M);
  }

  /* request duration */
  tme = 0;
  tmems = 0;
  if(T) {
    stripNum(&T);
    tme = atol(T);
  }
  if(t) {
    stripNum(&t);
    tmems= atol(t);
    tme = tmems / 1000;
  }
  if(D) {
    stripNum(&D);
    tmems = atol(D);
    tmems = tmems / 1000;
    tme = tmems / 1000;
  }

  if(m_offline_count) {
    updateClient(pool, T, t, D, S, BI, B, R, I, U, Q, E, k, C, M, ct, tme, tmems, m);
  } else if(m_offline_url) {
    if((tmems) == 0 && (tme > 0)) {
      tmems = 1000 * tme;
    }
    updateUrl(pool, R, S, tmems);
  } else {
    updateRec(m_stat_rec, T, t, D, S, s, a, A, BI, B, R, I, U, Q, E, k, C, M, tme, tmems);
    if(rec) {
      updateRec(rec, T, t, D, S, s, a, A, BI, B, R, I, U, Q, E, k, C, M, tme, tmems);
    }
  }
  qs_csUnLock();

  if(m_verbose && m_off) {
    printf("[%ld] I=[%s] U=[%s] B=[%s] i=[%s] S=[%s] T=[%ld](%ld) Q=[%s] E=[%s] k=[%s] R=[%s]\n", m_lines,
           I == NULL ? "(null)" : I,
           U == NULL ? "(null)" : U,
           B == NULL ? "(null)" : B,
           BI == NULL ? "(null)" : BI,
           S == NULL ? "(null)" : S,
           tme, tmems,
           Q == NULL ? "(null)" : Q,
           E == NULL ? "(null)" : E,
           k == NULL ? "(null)" : k,
           R == NULL ? "(null)" : R
           );
  }
  line[0] = '\0';
}

/*
 * convert month string to int
 */
static int mstr2i(const char *m) {
  if(strcmp(m, "Jan") == 0) return 1;
  if(strcmp(m, "Feb") == 0) return 2;
  if(strcmp(m, "Mar") == 0) return 3;
  if(strcmp(m, "Apr") == 0) return 4;
  if(strcmp(m, "May") == 0) return 5;
  if(strcmp(m, "Jun") == 0) return 6;
  if(strcmp(m, "Jul") == 0) return 7;
  if(strcmp(m, "Aug") == 0) return 8;
  if(strcmp(m, "Sep") == 0) return 9;
  if(strcmp(m, "Oct") == 0) return 10;
  if(strcmp(m, "Nov") == 0) return 11;
  if(strcmp(m, "Dec") == 0) return 12;
  return 0;
}

/**
 * Extracts the time from the log line using the 
 * Apache access default time format (%t)
 */
static time_t getMinutesAccessLog(char *line, regmatch_t ma) {
  time_t minutes = 0;
  int buf_len = ma.rm_eo - ma.rm_so + 1;
  char buf[buf_len];
  strncpy(buf, &line[ma.rm_so], ma.rm_eo - ma.rm_so);
  buf[ma.rm_eo - ma.rm_so] = '\0';
  /* dd/MMM/yyyy:hh:mm:ss */
  /* cut seconds */
  buf[strlen(buf)-3] = '\0';
  /* get minutes */
  minutes = minutes + (atoi(&buf[strlen(buf)-2]));
  /* cut minutes */
  buf[strlen(buf)-3] = '\0';
  /* get hours */
  minutes = minutes + (atoi(&buf[strlen(buf)-2]) * 60);
  
  /* store date information */
  {
    char *year;
    char *month;
    char *day;
    /* cut hours */
    buf[strlen(buf)-3] = '\0';
    year = &buf[strlen(buf)-4];
    /* cut year */
    buf[strlen(buf)-5] = '\0';
    month = &buf[strlen(buf)-3];
    /* cut month */
    buf[strlen(buf)-4] = '\0';
    day = buf;
    snprintf(m_date_str, sizeof(m_date_str), "%s.%02d.%s", day, mstr2i(month), year);
  }
  return minutes;
}

/**
 * Extracts the time from the log line using the 
 * the time patterns "yyyy mm dd hh:mm:ss,mmm" or
 * "yyyy mm dd hh:mm:ss.mmm"
 */
static time_t getMinutesJLog(char *line, regmatch_t ma) {
  time_t minutes = 0;
  int buf_len = ma.rm_eo - ma.rm_so + 1;
  char buf[buf_len];
  strncpy(buf, &line[ma.rm_so], ma.rm_eo - ma.rm_so);
  buf[ma.rm_eo - ma.rm_so] = '\0';
  /* yyyy mm dd hh:mm:ss,mmm */
  /* cut seconds */
  buf[strlen(buf)-7] = '\0';
  /* get minutes */
  minutes = minutes + (atoi(&buf[strlen(buf)-2]));
  /* cut minutes */
  buf[strlen(buf)-3] = '\0';
  /* get hours */
  minutes = minutes + (atoi(&buf[strlen(buf)-2]) * 60);
  /* store date information */
  {
    char *year;
    char *month;
    char *day;
    /* cut hours */
    buf[strlen(buf)-3] = '\0';
    day = &buf[strlen(buf)-2];
    /* cut day */
    buf[strlen(buf)-3] = '\0';
    month = &buf[strlen(buf)-2];
    /* cut month */
    buf[strlen(buf)-3] = '\0';
    year = buf;
    snprintf(m_date_str, sizeof(m_date_str), "%s.%s.%s", day, month, year);
  }
  return minutes;
}

/*
 * gets today's time in minutes from the access log line
 */
static time_t getMinutes(char *line) {
  regmatch_t ma[2];
  if(regexec(&m_trx_access, line, 1, ma, 0) == 0) {
    return getMinutesAccessLog(line, ma[0]);
  }
  if(regexec(&m_trx_j, line, 1, ma, 0) == 0) {
    return getMinutesJLog(line, ma[0]);
  }
  if(regexec(&m_trx_g, line, 2, ma, 0) == 0) {
    time_t minutes = 0;
    int len = ma[1].rm_eo - ma[1].rm_so;
    char buf[len+1];
    strncpy(buf, &line[ma[1].rm_so], len);
    buf[len] = '\0';
    /* hh:mm */
    buf[2] = '\0';
    minutes = atoi(buf) * 60;
    minutes = minutes + atoi(&buf[3]);
    return minutes;
  }
  // unknown format (not relevant for "-pu"/"-puc" but for "-p" mode)
  if(m_offline_url == 0) {
    fprintf(stdout, "F(%ld)", m_lines);
  }
  return 0;
}

/*
 * reads from stdin and calls updateStat()
 * => used for real time analysis
 */
static void readStdin(apr_pool_t *pool, const char *cstr) {
  char line[MAX_LINE];
  int line_len;
  while(fgets(line, sizeof(line), stdin) != NULL) {
    line_len = strlen(line) - 1;
    while(line_len > 0) { // cut tailing CR/LF
      if(line[line_len] >= ' ') {
        break;
      }
      line[line_len] = '\0';
      line_len--;
    }
    updateStat(pool, cstr, line);
  }
}

/*
 * reads from stdin and calls updateStat()
 * and printAndResetStat()
 * processes the time information from the
 * access log lines
 * => used for offline analysis
 */
static void readStdinOffline(apr_pool_t *pool, const char *cstr) {
  char line[MAX_LINE];
  char buf[32];
  time_t unitTime = 0;
  int line_len;
  FILE *outdev = stdout;
  if(m_offline_count || m_offline_url) {
    outdev = stderr;
  }
  while(fgets(line, sizeof(line), stdin) != NULL) {
    time_t l_time;
    line_len = strlen(line) - 1;
    while(line_len > 0) { // cut tailing CR/LF
      if(line[line_len] >= ' ') {
        break;
      }
      line[line_len] = '\0';
      line_len--;
    }
    l_time = getMinutes(line);
    m_offline_data = 1;
    if(unitTime == 0) {
      unitTime = l_time;
      qs_setTime(unitTime * 60);
    }
    if(unitTime == l_time) {
      updateStat(pool, cstr, line);
    } if(l_time < unitTime) {
      /* leap in time... */
      updateStat(pool, cstr, line);
      fprintf(outdev, "X");
      fflush(outdev);
      unitTime = 0;
    } else {
      if(l_time > unitTime) {
        if(!m_verbose) {
          if(m_f != stdout) {
            fprintf(outdev, ".");
            fflush(outdev);
          }
        }
      }
      while(l_time > unitTime) {
        unitTime++;
        snprintf(buf, sizeof(buf), "%s %.2ld:%.2ld:00", m_date_str, unitTime/60, unitTime%60);
        if(m_offline) {
          printAndResetStat(buf);
        }
        qs_setTime(unitTime * 60);;
      }
      updateStat(pool, cstr, line);
    }
  }
  if(m_offline_data) {
    snprintf(buf, sizeof(buf), "%s %.2ld:%.2ld:00", m_date_str, unitTime/60, unitTime%60);
    if(m_offline) {
      printAndResetStat(buf);
    }
  }
}

/*
 * calls printAndResetStat() every minute
 * => used for real time analysis
 */
static void *loggerThread(void *argv) {
  char buf[1024];
  while(1) {
    struct tm *ptr;
    time_t tm = time(NULL);
    time_t w = tm / LOG_INTERVAL * LOG_INTERVAL + LOG_INTERVAL;
    sleep(w - tm);

    tm = time(NULL);
    ptr = localtime(&tm);
    strftime(buf, sizeof(buf), "%d.%m.%Y %H:%M:%S", ptr);

    printAndResetStat(buf);
    if(m_rotate && m_file_name[0]) {
      strftime(buf, sizeof(buf), "%H:%M", ptr);
      if(strcmp(buf, "23:59") == 0) {
        char arch[MAX_LINE];
        char arch2[MAX_LINE];
        strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", ptr);
        snprintf(arch, sizeof(arch), "%s.%s", m_file_name, buf);
        snprintf(arch2, sizeof(arch), "%s.%s", m_file_name2, buf);
        if(fclose(m_f) != 0) {
          qerror("failed to close file '%s': %s", m_file_name, strerror(errno));
        }
        if(rename(m_file_name, arch) != 0) {
          qerror("failed to move file '%s': %s", arch, strerror(errno));
        }
        qs_deleteOldFiles(m_file_name, m_generations);
        m_f = fopen(m_file_name, "a+");
        if(m_f2) {
          fclose(m_f2);
          rename(m_file_name2, arch2);
          qs_deleteOldFiles(m_file_name2, m_generations);
          m_f2 = fopen(m_file_name2, "a+");
        }
      }
    }
  }
  return NULL;
}

/**
 * usage text
 */
static void usage(const char *cmd, int man) {
  if(man) {
    //.TH [name of program] [section number] [center footer] [left footer] [center header]
    printf(".TH %s 1 \"%s\" \"mod_qos utilities %s\" \"%s man page\"\n", qs_CMD(cmd), man_date,
           man_version, cmd);
  }
  printf("\n");
  if(man) {
    printf(".SH NAME\n");
  }
  qs_man_print(man, "%s - collects request statistics from access log data.\n", cmd);
  printf("\n");

  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -f <format_string> -o <out_file> [-p[c|u[c]] [-v]] [-x [<num>]] [-u <name>] [-m] [-c <path>]\n", man ? "" : "Usage: ", cmd);
  printf("\n");

  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "%s is a real time access log analyzer. It collects the data from stdin.\n", cmd);
  qs_man_print(man, "The output is written to the specified file every minute and includes the\n");
  qs_man_println(man, "following entries:\n");
  qs_man_println(man, "  - requests per second ("NRS")\n");
  qs_man_println(man, "  - number of requests within measured time (req)\n");
  qs_man_println(man, "  - bytes sent to the client per second ("NBS")\n");
  qs_man_println(man, "  - bytes received from the client per second ("NBIS")\n");
  qs_man_println(man, "  - response status codes within the last minute (1xx,2xx,3xx,4xx,5xx)\n");
  qs_man_println(man, "  - average response duration ("NAV")\n");
  qs_man_println(man, "  - average response duration in milliseconds ("NAVMS")\n");
  qs_man_println(man, "  - distribution of response durations in seconds within the last minute\n");
  qs_man_print(man, "    (<1s,1s,2s,3s,4s,5s,>5s)\n");
  if(man) printf("\n");
  qs_man_println(man, "  - distribution of response durations faster than a second within the last minute\n");
  qs_man_print(man, "    (0-49ms,50-99ms,100-499ms,500-999ms)\n");
  if(man) printf("\n");
  qs_man_println(man, "  - number of established (new) connections within the measured time (esco)\n");
  qs_man_println(man, "  - average system load (sl)\n");
  qs_man_println(man, "  - free memory (m) (not available for all platforms)\n");
  qs_man_println(man, "  - number of client ip addresses seen withn the last %d seconds (ip)\n", ACTIVE_TIME);
  qs_man_println(man, "  - number of different users seen withn the last %d seconds (usr)\n", ACTIVE_TIME);
  qs_man_println(man, "  - number of events identified by the 'E' format character\n");
  qs_man_println(man, "  - number of mod_qos events within the last minute (qV=create session,\n");
  qs_man_print(man, "    qv=VIP IP,qS=session pass, qD=access denied, qK=connection closed, qT=dynamic\n");
  qs_man_print(man, "    keep-alive, qL=request/response slow down, qs=serialized request, \n");
  qs_man_print(man, "    qA=connection abort, qU=new user tracking cookie)\n");
  printf("\n");

  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -f <format_string>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines the log data format and the positions of data\n");
  qs_man_print(man, "     elements processed by this utility.\n");
  qs_man_print(man, "     See to the 'LogFormat' directive of the httpd.conf file\n");
  qs_man_print(man, "     to see the format definitions of the servers access log data.\n");
  if(man) printf("\n");
  qs_man_println(man, "     %s knows the following elements:\n", cmd);
  qs_man_println(man, "     I defines the client ip address (%%h)\n");
  qs_man_println(man, "     R defines the request line (%%r)\n");
  qs_man_println(man, "     S defines HTTP response status code (%%s)\n");
  qs_man_println(man, "     B defines the transferred bytes (%%b or %%O)\n");
  qs_man_println(man, "     i defines the received bytes (%%I)\n");
  qs_man_println(man, "     D defines the request duration in microseconds (%%D)\n");
  qs_man_println(man, "     t defines the request duration in milliseconds (may be used instead of D)\n");
  qs_man_println(man, "     T defines the request duration in seconds (may be used instead of D or t) (%%T)\n");
  qs_man_println(man, "     k defines the number of keepalive requests on the connection (%%k)\n");
  qs_man_println(man, "     U defines the user tracking id (%%{mod_qos_user_id}e)\n");
  qs_man_println(man, "     Q defines the mod_qos_ev event message (%%{mod_qos_ev}e)\n");
  qs_man_println(man, "     C defines the element for the detailed log (-c option), e.g. \"%%U\"\n");
  qs_man_println(man, "     s arbitrary counter to add up (sum within a minute)\n");
  qs_man_println(man, "     a arbitrary counter to build an average from (average per request)\n");
  qs_man_println(man, "     A arbitrary counter to build an average from (average per request)\n");
  qs_man_println(man, "     M arbitrary counter to measure the maximum value reached (peak)\n");
  qs_man_println(man, "     E comma separated list of event strings\n");
  qs_man_println(man, "     c content type (%%{content-type}o), available in -pc mode only\n");
  qs_man_println(man, "     m request method (GET/POST) (%%m), available in -pc mode only\n");
  qs_man_println(man, "     . defines an element to ignore (unknown string)\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -o <out_file>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifies the file to store the output to. stdout is used if this option\n");
  qs_man_print(man, "     is not defined.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -p\n");
  if(man) printf("\n");
  qs_man_print(man, "     Used for post processing when reading the log data from a file (cat/pipe).\n");
  qs_man_print(man, "     %s is started using it's offline mode (extracting the time stamps from\n", cmd);
  qs_man_print(man, "     the log lines) in order to process existing log files.\n");
  qs_man_print(man, "     The option \"-pc\" may be used alternatively if you want to gather request\n");
  qs_man_print(man, "     information per client (identified by IP address (I) or user tracking id (U)\n");
  qs_man_print(man, "     showing how many request each client has performed within the captured period\n");
  qs_man_print(man, "     of time). \"-pc\" supports the format characters IURSBTtDkMEcm.\n");
  qs_man_print(man, "     The option \"-pu\" collects statistics on a per URL level (supports format\n");
  qs_man_print(man, "     characters RSTtD).\n");
  qs_man_print(man, "     \"-puc\" is very similar to \"-pu\" but cuts the end (handler) of each URL.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -v\n");
  if(man) printf("\n");
  qs_man_print(man, "     Verbose mode.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -x [<num>]\n");
  if(man) printf("\n");
  qs_man_print(man, "     Rotates the output file once a day (move). You may specify the number of\n");
  qs_man_print(man, "     rotated files to keep. Default are %d.\n", QS_GENERATIONS);
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -u <name>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Becomes another user, e.g. www-data.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -m\n");
  if(man) printf("\n");
  qs_man_print(man, "     Calculates free system memory every minute.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -c <path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Enables the collection of log statistics for different request types.\n");
  qs_man_print(man, "     'path' specifies the necessary rule file. Each rule consists of a rule\n");
  qs_man_print(man, "     identifier and a regular expression to identify a request seprarated\n");
  qs_man_print(man, "     by a colon, e.g., 01:^(/a)|(/c). The regular expressions are matched against\n");
  qs_man_print(man, "     the log data element which has been identified by the 'C' format character.\n");

  printf("\n");
  if(man) {
    printf(".SH VARIABLES\n");
  } else {
    printf("Variables\n");
  }
  qs_man_print(man, "The following environment variables are known to %s:\n", cmd);
  if(man) printf("\n");
  if(man) printf(".TP\n");
  qs_man_print(man, "  "QSEVENTPATH"=<path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines a file containing a comma or new line separated list\n");
  qs_man_print(man, "     of known event strings expected within the log filed identified\n");
  qs_man_print(man, "     by the 'E' format character.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  "QSCOUNTERPATH"=<path>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Defines a file containing a by new line separated list of rules which\n");
  qs_man_print(man, "     reflect possible QS_ClientEventLimitCount directive settings (for\n");
  qs_man_print(man, "     simulation purpose / -pc option). The 'E' format character defines the event\n");
  qs_man_print(man, "     string in the log to match (literal string) the 'event1' and 'event2' event\n");
  qs_man_print(man, "     names against.\n");
  printf("\n");
  if(man) printf("\n");
  qs_man_print(man, "     Rule syntax: <name>:<event1>-<n>*<event2>/<duration>=<limit>\n");
  printf("\n");
  qs_man_println(man, "     'name' defines the name you have given to the rule entry and is logged along with\n");
  qs_man_print(man, "      with the number of times the 'limit' has been reached within the 'duration'.\n");
  if(man) printf("\n");
  qs_man_println(man, "     'event1' defines the variable name (if found in 'E') to increment the counter.\n");
  qs_man_println(man, "     'event2' defines the variable name (if found in 'E') to decrement the counter (and\n");
  qs_man_print(man, "      the parameter 'n' defines by how much).\n");
  if(man) printf("\n");
  qs_man_println(man, "     'duration' defines the measure interval (in seconds) used for the\n");
  qs_man_print(man, "      QS_ClientEventLimitCount directive.\n");
  if(man) printf("\n");
  qs_man_println(man, "     'limit' defines the threshold (number) defined for the QS_ClientEventLimitCount\n");
  qs_man_print(man, "      directive.\n");
  if(man) printf("\n");
  printf("\n");
  qs_man_print(man, "     Note: If the 'name' parameter is prefixed by 'STATUS', the rule is applied against\n");
  qs_man_print(man, "     the HTTP status code 'S' and the 'event1' string shall contain a list of relevant\n");
  qs_man_print(man, "     status codes separated by an underscore (while 'event2' is ignored).\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
    printf("Configuration using pipped logging:\n");
    printf("\n");
  } else {
    printf("Example configuration using pipped logging:\n");
  }
  qs_man_println(man, "  CustomLog \"|/usr/bin/%s -f ISBDQ -x -o /var/log/apache/stat.csv\" \"%%h %%>s %%b %%D %%{mod_qos_ev}e\"\n", cmd);
  printf("\n");
  if(man) {
    printf("Post processing:\n");
    printf("\n");
  } else {
    printf("Example for post processing:\n");
  }
  qs_man_println(man, "  LogFormat \"%%t %%h \\\"%%r\\\" %%>s %%b \\\"%%{User-Agent}i\\\" %%T\"\n");
  qs_man_println(man, "  cat access.log | %s -f ..IRSB.T -o stat.csv -p\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qshead(1), qslogger(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://mod-qos.sourceforge.net/\n");
  } else {
    printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  }
  if(man) {
    exit(0);
  } else {
    exit(1);
  }
}

/**
 * Loads the rule files. Each rule (pattern) is prefixed by an id.
 *
 * @param confFile Path to the rule file to load
 * @return
 */
static stat_rec_t *loadRule(apr_pool_t *pool, const char *confFile) {
  char line[MAX_LINE];
  FILE *file = fopen(confFile, "r"); 
  stat_rec_t *rec = NULL;
  stat_rec_t *prev = NULL;
  stat_rec_t *next = NULL;
  if(file == NULL) {
    qerror("could not read file '%s': ", confFile, strerror(errno));
    exit(1);
  }
  while(!qs_getLinef(line, sizeof(line), file)) {
    char *id = line;
    char *p = strchr(line, RULE_DELIM);
    if(p) {
      p[0] = '\0';
      p++;
      if(m_verbose) {
        printf("load rule %s: %s\n", id, p);
      }
      next = createRec(pool, id, p);
      if(rec == NULL) {
        // first record
        rec = next;
      }
      if(prev) {
        // has previous, append it to the list
        prev->next = next;
      } else {
        // sole record, no next
        rec->next = NULL;
      }
      // prev points now to the new record
      prev = next;
    }
  }
  fclose(file);
  return rec;
}

int main(int argc, const char *const argv[]) {
  const char *config = NULL;
  const char *file = NULL;
  const char *confFile = NULL;
  const char *cmd = strrchr(argv[0], '/');
  const char *username = NULL;
  pthread_attr_t *tha = NULL;
  pthread_t tid;
  pthread_attr_t *thagc = NULL;
  pthread_t tidgc;
  apr_pool_t *pool;
  int t;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  m_stat_rec = createRec(pool, "", "");

  for(t = 0; t < NUM_EVENT_TABLES; t++) {
    m_ip_list[t] = apr_table_make(pool, 15000);
    m_user_list[t] = apr_table_make(pool, 15000);
  }
  m_gc_event_list = calloc(MAX_EVENT_ENTRIES, sizeof(qs_event_t *));

  qs_csInitLock();
  qs_setExpiration(ACTIVE_TIME);
  if(cmd == NULL) {
    cmd = argv[0];
  } else {
    cmd++;
  }
  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-f") == 0) { /* this is the format string */
      if (--argc >= 1) {
        config = *(++argv);
        if(strchr(config, 'i')) {
          // enable ib/s
          m_stat_rec->i_byte_count = 0;
        }
        if(strchr(config, 'k')) {
          // enable esco
          m_stat_rec->connections = 0;
        }
        if(strchr(config, 'c')) {
          // enable content type
          m_ct = 1;
        }
        if(strchr(config, 'D') || strchr(config, 't')) {
          // enable average duration in ms
          m_avms = 1;
        }
        if(strchr(config, 'm')) {
          m_methods = 1;
        }
        if(strchr(config, 's') || strchr(config, 'a') || strchr(config, 'A') || strchr(config, 'M')) {
          // enable custom counter
          m_customcounter = 1;
        }
        if(strchr(config, 'Q')) {
          m_hasEV = 1;
        }
      }
    } else if(strcmp(*argv,"-o") == 0) { /* this is the out file */
      if (--argc >= 1) {
        file = *(++argv);
      }
    } else if(strcmp(*argv,"-u") == 0) { /* switch user id */
      if (--argc >= 1) {
        username = *(++argv);
      }
    } else if(strcmp(*argv,"-c") == 0) { /* custom patterns (e.g. url pattern list, format: <id>':'<pattern>) */
      if (--argc >= 1) {
        confFile = *(++argv);
      }
    } else if(strcmp(*argv,"-p") == 0) {   /* activate offline analysis */
      m_offline = 1;
      qs_set2OfflineMode();
    } else if(strcmp(*argv,"-ps") == 0) {   /* activate offline analysis (inckl. summary) */
      m_offline = 1;
      m_offline_s = 1;
      qs_set2OfflineMode();
    } else if(strcmp(*argv,"-pc") == 0) {  /* activate offline counting analysis */
      m_offline_count = 1;
      qs_set2OfflineMode();
    } else if(strcmp(*argv,"-pu") == 0) {  /* activate offline url analysis */
      m_offline_url = 1;
      qs_set2OfflineMode();
    } else if(strcmp(*argv,"-puc") == 0) { /* activate offline url analysis */
      m_offline_url = 1;
      m_offline_url_cropped = 1;
      qs_set2OfflineMode();
    } else if(strcmp(*argv,"-m") == 0) { /* activate memory usage */
      m_mem = 1;
    } else if(strcmp(*argv,"-v") == 0) {
      m_verbose = 1;
    } else if(strcmp(*argv,"-x") == 0) { /* activate log rotation */
      m_rotate = 1;
      if(argc > 1) {
        if(*argv[1] >= '0' && *argv[1] <= '9') {
          argc--;
          argv++;
          m_generations = atoi(*argv);
        }
      }
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    } else {
      qerror("unknown option '%s'", *argv);
      exit(1);
    }
    argc--;
    argv++;
  }
  m_off = m_offline || m_offline_count || m_offline_url;
  if(m_off) {
    if(nice(10) == -1) {
      fprintf(stderr, "ERROR, failed to change nice value: %s\n", strerror(errno));
    }
    /* init time pattern regex, std apache access log "dd/MMM/yyyy:hh:mm:ss" */
    regcomp(&m_trx_access, 
            "[0-9]{2}/[a-zA-Z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}",
            REG_EXTENDED);
    /* other time patterns: "yyyy mm dd hh:mm:ss,mmm" or "yyyy mm dd hh:mm:ss.mmm"
       resp  "yyyy-mm-dd hh:mm:ss,mmm" or "yyyy-mm-dd hh:mm:ss.mmm" */
    regcomp(&m_trx_j,
            "[0-9]{4}[ -]{1}[0-9]{2}[ -]{1}[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}[,.]{1}[0-9]{3}",
            REG_EXTENDED);
    /* fallback to generic " hh:mm:ss " pattern */
    regcomp(&m_trx_g,
            " ([0-9]{2}:[0-9]{2}):[0-9]{2} ",
            REG_EXTENDED);
  }

  /*
   * offline url mod
   */
  if(m_offline_url) {
    int i;
    apr_table_entry_t *entry;
    m_url_entries = apr_table_make(pool, MAX_CLIENT_ENTRIES + 1);
    if(config == NULL) usage(cmd, 0);
    readStdinOffline(pool, config);
    fprintf(stderr, ".\n");

    m_f = stdout;
    if(file) {
      m_f = fopen(file, "a+");
      if(!m_f) {
        m_f = stdout;
      }
    }
    entry = (apr_table_entry_t *) apr_table_elts(m_url_entries)->elts;
    for(i = 0; i < apr_table_elts(m_url_entries)->nelts; i++) {
      url_rec_t *url_rec = (url_rec_t *)entry[i].val;
      fprintf(m_f, "req;%ld;"
              "1xx;%ld;2xx;%ld;3xx;%ld;4xx;%ld;5xx;%ld;"
              NAVMS";%lld;%s\n",
              url_rec->request_count,
              url_rec->status_1,
              url_rec->status_2,
              url_rec->status_3,
              url_rec->status_4,
              url_rec->status_5,
              url_rec->request_count ? (url_rec->duration_count_ms / url_rec->request_count) : 0,
              entry[i].key);
      
    }
    if(file && m_f != stdout) {
      fclose(m_f);
    }
    return 0;
  }

  /*
   * offline count mode creates statistics
   * on a per client basis (e.g. per source
   * ip or user id using the user tracking
   * feature of mod_qos)
   */
  if(m_offline_count) {
    int i;
    apr_table_entry_t *entry;
    if(config == NULL) usage(cmd, 0);
    m_client_entries = apr_table_make(pool, MAX_CLIENT_ENTRIES + 1);
    readStdinOffline(pool, config);
    fprintf(stderr, ".\n");
    entry = (apr_table_entry_t *) apr_table_elts(m_client_entries)->elts;
    m_f = stdout;
    if(file) {
      m_f = fopen(file, "a+");
      if(!m_f) {
        m_f = stdout;
      }
    }
    for(i = 0; i < apr_table_elts(m_client_entries)->nelts; i++) {
      client_rec_t *client_rec = (client_rec_t *)entry[i].val;
      char esco[256];
      char m[256];
      /* ci (coverage index): low value indicates that we have seen the client
                              at the end or beginning of the file (maybe not all
                              requests due to log rotation) */
      long coverage = m_lines ? (client_rec->firstLine * 100 / m_lines) : 0;
      long coverageend = m_lines ? (100 - ((client_rec->lastLine * 100) / m_lines)) : 0;
      if(coverageend < coverage) {
        coverage = coverageend;
      }
      esco[0] = '\0';
      if(m_stat_rec->connections != -1) {
        sprintf(esco, "esco;%ld;", client_rec->connections);
      }
      m[0] = '\0';
      if(m_methods) {
        sprintf(m, "GET;%ld;POST;%ld;",
                client_rec->get,
                client_rec->post);
      }
      if(m_avms == 0) {
        // no ms available
        client_rec->duration_count_ms = 1000 * client_rec->duration;
      } else {
        // improve accuracy (rounding errors):
        client_rec->duration = client_rec->duration_count_ms / 1000;
      }
      fprintf(m_f, "%s;req;%ld;errors;%ld;duration;%ld;bytes;%lld;"
              "1xx;%ld;2xx;%ld;3xx;%ld;4xx;%ld;5xx;%ld;304;%ld;"
              "av;%lld;"NAVMS";%lld;<1s;%ld;1s;%ld;2s;%ld;3s;%ld;4s;%ld;5s;%ld;>5s;%ld;"
              "%s"
              "%s"
              "ci;%ld;",
              entry[i].key,
              client_rec->request_count,
              client_rec->error_count,
              client_rec->end_s - client_rec->start_s,
              client_rec->byte_count,
              client_rec->status_1,
              client_rec->status_2,
              client_rec->status_3,
              client_rec->status_4,
              client_rec->status_5,
              client_rec->status_304,
              client_rec->request_count ? (client_rec->duration / client_rec->request_count) : 0,
              client_rec->request_count ? (client_rec->duration_count_ms / client_rec->request_count) : 0,
              client_rec->duration_0,
              client_rec->duration_1,
              client_rec->duration_2,
              client_rec->duration_3,
              client_rec->duration_4,
              client_rec->duration_5,
              client_rec->duration_6,
              esco,
              m,
              coverage);
      if(m_customcounter) {
        fprintf(m_f, "M;%ld;",
                client_rec->max);
      }
      if(client_rec->counters) {
        int c;
        apr_table_entry_t *centry = (apr_table_entry_t *) apr_table_elts(client_rec->counters)->elts;
        for(c = 0; c < apr_table_elts(client_rec->counters)->nelts; c++) {
          counter_rec_t *cr = (counter_rec_t *)centry[c].val;
          fprintf(m_f, "%s;%d;", cr->name, cr->total);
        }
      }
      if(m_ct) {
        fprintf(m_f, "html;%ld;css/js;%ld;img;%ld;other;%ld;",
                client_rec->html,
                client_rec->cssjs,
                client_rec->img,
                client_rec->other);
      }
      if(apr_table_elts(client_rec->events)->nelts > 0) {
        int k;
        apr_table_entry_t *client_entry = (apr_table_entry_t *) apr_table_elts(client_rec->events)->elts;
        for(k = 0; k < apr_table_elts(client_rec->events)->nelts; k++) {
          const char *eventName = client_entry[k].key;
          int *eventVal = (int *)client_entry[k].val;
          fprintf(m_f, "%s;%d;", eventName, *eventVal);
          (*eventVal) = 0;
        }
      }
      fprintf(m_f, "\n");
    }
    if(file && (m_f != stdout)) {
      fclose(m_f);
    }
    return 0;
  }

  /* requires at least a format string */
  if(config == NULL) usage(cmd, 0);

  qs_setuid(username, cmd);

  if(file) {
    m_f = fopen(file, "a+"); 
    if(m_f == NULL) {
      qerror("could not open file for writing '%s': %s", file, strerror(errno));
      exit(1);
    }
    if(strlen(file) > (sizeof(m_file_name) - strlen(".yyyymmddHHMMSS  ") - strlen(LOG_DET))) {
      qerror("file name too long '%s'", file);
      exit(1);
    }
    strcpy(m_file_name, file);
  } else {
    m_file_name[0] = '\0';
    m_f = stdout;
  }

  if(confFile) {
    if(file == NULL) {
      qerror("option '-c' can only be used in conjunction with option '-o'");
      exit(1);
    }
    snprintf(m_file_name2, sizeof(m_file_name2), "%s"LOG_DET, m_file_name);
    if(strchr(config, 'C') == NULL) {
      qerror("you need to add 'C' to the format string when enabling the pattern list (-c)");
      exit(1);
    }
    m_stat_sub = loadRule(pool, confFile);
    m_f2 = fopen(m_file_name2, "a+");
    if(m_f == NULL) {
      qerror("could not open file for writing '%s': %s", m_file_name2, strerror(errno));
      exit(1);
    }
  }

  /*
   * Offline mode reads an existing log file
   * adjusting a virtual clock based on
   * the date string match of the log
   * enties. */
  if(m_offline) {
    fprintf(stderr, "[%s]: offline mode\n", cmd);
    m_date_str[0] = '\0';
    readStdinOffline(pool, config);
    if(!m_verbose) {
      fprintf(stdout, "\n");
    }
    if(m_offline_s) {
      int p;
      int min = 0;
      int max = 50;
      printf("\n");
      printf("      requests: %llu\n", m_stat_rec->total.lines);
      printf("       average: %llums\n", m_stat_rec->total.ms/m_stat_rec->total.lines);
      for(p = 0; p <20; p++) {
        printf("%3dms - %4dms: %lld\n", min, max, m_stat_rec->total.pivot[p]);
        min = max;
        max += 50;
      }
      printf("1000ms+       : %lld\n", m_stat_rec->total.pivot[20]);
    }
  } else {
    /* standard mode reads data from
     * stdin and uses a separate thread
     * to write the data every minute. 
     */
    pthread_create(&tid, tha, loggerThread, NULL);
    pthread_create(&tidgc, thagc, gcThread, NULL);
    readStdin(pool, config);
  }
  if(file && (m_f != stdout)) {
    fclose(m_f);
  }
  return 0;
}
