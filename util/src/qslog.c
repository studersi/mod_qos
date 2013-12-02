/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * Utilities for the quality of service module mod_qos.
 *
 * Real time access log data correlation.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2013 Pascal Buchbinder
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

static const char revision[] = "$Id: qslog.c,v 1.72 2013-12-02 20:43:24 pbuchbinder Exp $";

#include <stdio.h>
#include <error.h>
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
#define LOG_DET ".detailed"
#define RULE_DELIM ':'
#define MAX_CLIENT_ENTRIES 25000
#define QS_GENERATIONS 14
#define EVENT_DELIM ','
#define QSEVENTPATH "QSEVENTPATH" /* varibale name to find event definitions */

/* ----------------------------------
 * structures
 * ---------------------------------- */

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
  apr_table_t *events;
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

  long status_1;
  long status_2;
  long status_3;
  long status_4;
  long status_5;

  long qos_v;
  long qos_s;
  long qos_d;
  long qos_k;
  long qos_t;
  long qos_l;
  long qos_ser;

  apr_table_t *events;
  apr_pool_t *pool;
} stat_rec_t;

/* ----------------------------------
 * global stat counter
 * ---------------------------------- */
static stat_rec_t* m_stat_rec;
static stat_rec_t* m_stat_sub = NULL;

static qs_event_t *m_ip_list = NULL;
static qs_event_t *m_user_list = NULL;

/* output file */
static FILE *m_f = NULL;
static FILE *m_f2 = NULL;
static char  m_file_name[MAX_LINE];
static char  m_file_name2[MAX_LINE];
static int   m_rotate = 0;
static int   m_generations = QS_GENERATIONS;
/* regex to search the time string */
static regex_t m_trx;
static regex_t m_trx2;
/* real time mode (default) or offline */
static int   m_off = 0;
static int   m_offline = 0;
static int   m_offline_data = 0;
static char  m_date_str[MAX_LINE];
static int   m_mem = 0;
static int   m_avms = 0;
static int   m_ct = 0;
static int   m_customcounter = 0;
static apr_table_t *m_client_entries = NULL;
static int   m_max_client_entries = 0;
static int   m_offline_count = 0;
static apr_table_t *m_url_entries = NULL;
static int   m_offline_url = 0;
static int   m_methods = 0;
/* debug/offline */
static long  m_lines = 0;
static int   m_verbose = 0;

/**
 * Helper to print an error message when terminating
 * the programm due to an unexpected error.
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
    /* experimental code using vmstat */
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
            // free memory only (ignores cache on linux)
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
    sprintf(custom, "s;%llu;a;%llu;A;%llu;",
            stat_rec->sum,
            stat_rec->average / (stat_rec->average_count == 0 ? 1 : stat_rec->average_count),
            stat_rec->averAge / (stat_rec->averAge_count == 0 ? 1 : stat_rec->averAge_count));
  }
  if(main) {
    sprintf(ip, "ip;%ld;", qs_countEvent(&m_ip_list));
    sprintf(usr, "usr;%ld;", qs_countEvent(&m_user_list));
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
          NAV";%lld;"
          "<1s;%ld;"
          "1s;%ld;"
          "2s;%ld;"
          "3s;%ld;"
          "4s;%ld;"
          "5s;%ld;"
          ">5s;%ld;"
          "%s"
          "%s"
          "qV;%ld;"
          "qS;%ld;"
          "qD;%ld;"
          "qK;%ld;"
          "qT;%ld;"
          "qL;%ld;"
          "qs;%ld;"
          "%s"
          ,
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
          stat_rec->duration_count/(stat_rec->line_count == 0 ? 1 : stat_rec->line_count),
          stat_rec->duration_0,
          stat_rec->duration_1,
          stat_rec->duration_2,
          stat_rec->duration_3,
          stat_rec->duration_4,
          stat_rec->duration_5,
          stat_rec->duration_6,
          ip,
          usr,
          stat_rec->qos_v,
          stat_rec->qos_s,
          stat_rec->qos_d,
          stat_rec->qos_k,
          stat_rec->qos_t,
          stat_rec->qos_l,
          stat_rec->qos_ser,
          custom
          );
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
  stat_rec->status_1 = 0;
  stat_rec->status_2 = 0;
  stat_rec->status_3 = 0;
  stat_rec->status_4 = 0;
  stat_rec->status_5 = 0;
  stat_rec->duration_count = 0;
  stat_rec->duration_count_ms = 0;
  stat_rec->duration_0 = 0;
  stat_rec->duration_1 = 0;
  stat_rec->duration_2 = 0;
  stat_rec->duration_3 = 0;
  stat_rec->duration_4 = 0;
  stat_rec->duration_5 = 0;
  stat_rec->duration_6 = 0;
  stat_rec->qos_v = 0;
  stat_rec->qos_s = 0;
  stat_rec->qos_d = 0;
  stat_rec->qos_k = 0;
  stat_rec->qos_t = 0;
  stat_rec->qos_l = 0;
  stat_rec->qos_ser = 0;
  if(main) {
    if(!offline) {
      fprintf(f, "sl;%.2f;m;%s;",
              av[0], mem[0] ? mem : "-");
    } else {
      fprintf(f, "sl;-;m;-;");
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
      // suports multiple parsing of the event string
      restore[0] = EVENT_DELIM;
    }
  }
}

/**
 * Initializes the event table by the events specified within the
 * file whose path is defined by the QSEVENTPATH environment
 * variable.
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

  rec->status_1 = 0;
  rec->status_2 = 0;
  rec->status_3 = 0;
  rec->status_4 = 0;
  rec->status_5 = 0;

  rec->qos_v = 0;
  rec->qos_s = 0;
  rec->qos_d = 0;
  rec->qos_k = 0;
  rec->qos_t = 0;
  rec->qos_l = 0;
  rec->qos_ser = 0;

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
    fprintf(stdout, "E");
    return;
  }
  marker = strchr(R, ' ');
  if(marker == NULL) {
    fprintf(stdout, "E");
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
  url_rec = (url_rec_t *)apr_table_get(m_url_entries, R);
  if(url_rec == NULL) {
    if(apr_table_elts(m_url_entries)->nelts >= MAX_CLIENT_ENTRIES) {
      // limitation
      if(!m_max_client_entries) {
        fprintf(stderr, "\nreached max url enries (%d)\n", MAX_CLIENT_ENTRIES);
        m_max_client_entries = 1;
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
  url_rec->duration_count_ms += tmems;
}

/**
 * Updates the per client record
 */
static void updateClient(apr_pool_t *pool, char *T, char *t, char *D, char *S,
                         char *BI, char *B, char *R, char *I, char *U, char *Q,
                         char *E, char *k, char *C, char *ct, long tme, long tmems,
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
      if(!m_max_client_entries) {
        fprintf(stderr, "\nreached max client enries (%d)\n", MAX_CLIENT_ENTRIES);
        m_max_client_entries = 1;
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
    client_rec->events = apr_table_make(pool, 100);
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
  return;
}

/**
 * Updates standard record
 */
static void updateRec(stat_rec_t *rec, char *T, char *t, char *D, char *S,
                      char *s, char *a, char *A,
                      char *BI, char *B, char *R, char *I, char *U, char *Q,
                      char *E, char *k, char *C, long tme, long tmems) {
  if(Q != NULL) {
    if(strchr(Q, 'V') != NULL) {
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
  }
  if(E != NULL) {
    qs_updateEvents(rec->pool, E, rec->events);
  }
  if(I != NULL) {
    /* update/store client IP */
    qs_insertEvent(&m_ip_list, I);
  }
  if(U != NULL) {
    /* update/store user */
    qs_insertEvent(&m_user_list, U);
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
  char *a = NULL; /* avarage 1 */
  char *A = NULL; /* average 2 */
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
  tme = 0;
  if(T != NULL || t != NULL || D != NULL) {
    /* response duration */
    tmems = 0;
    if(T) {
      stripNum(&T);
      tme = atol(T);
    } else if(t) {
      stripNum(&t);
      tmems= atol(t);
      tme = tmems / 1000;
    } else if(D) {
      stripNum(&D);
      tmems = atol(D);
      tmems = tmems / 1000;
      tme = tmems / 1000;
    }
  }
  if(m_offline_count) {
    updateClient(pool, T, t, D, S, BI, B, R, I, U, Q, E, k, C, ct, tme, tmems, m);
  } else if(m_offline_url) {
    if((tmems) == 0 && (tme > 0)) {
      tmems = 1000 * tme;
    }
    updateUrl(pool, R, S, tmems);
  } else {
    updateRec(m_stat_rec, T, t, D, S, s, a, A, BI, B, R, I, U, Q, E, k, C, tme, tmems);
    if(rec) {
      updateRec(rec, T, t, D, S, s, a, A, BI, B, R, I, U, Q, E, k, C, tme, tmems);
    }
  }
  qs_csUnLock();

  if(m_verbose && m_off) {
    printf("[%ld] I=[%s] U=[%s] B=[%s] i=[%s] S=[%s] T=[%ld] Q=[%s] E=[%s] k=[%s]\n", m_lines,
           I == NULL ? "(null)" : I,
           U == NULL ? "(null)" : U,
           B == NULL ? "(null)" : B,
           BI == NULL ? "(null)" : BI,
           S == NULL ? "(null)" : S,
           tme,
           Q == NULL ? "(null)" : Q,
           E == NULL ? "(null)" : E,
           k == NULL ? "(null)" : k
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

/*
 * get the time in minutes from the access log line
 */
static time_t getMinutes(char *line) {
  regmatch_t ma;
  if(regexec(&m_trx, line, 1, &ma, 0) != 0) {
    if(regexec(&m_trx2, line, 1, &ma, 0) == 0) {
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
    } else {
      // unknown format
      fprintf(stdout, "E");
      return 0;
    }
  } else {
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
  if(m_offline_count) {
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
          fprintf(outdev, ".");
          fflush(outdev);
        }
      }
      while(l_time > unitTime) {
        snprintf(buf, sizeof(buf), "%s %.2ld:%.2ld:00", m_date_str, unitTime/60, unitTime%60);
        if(m_offline) {
          printAndResetStat(buf);
        }
        unitTime++;
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
    if(m_rotate) {
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
  qs_man_print(man, "%s%s -f <format_string> -o <out_file> [-p[c] [-v]] [-x [<num>]] [-u <name>] [-m] [-c <path>]\n", man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "%s is a real time access log analyzer. It collects\n", cmd);
  qs_man_print(man, "the data from stdin. The output is written to the specified\n");
  qs_man_println(man, "file every minute and includes the following entries:\n");
  qs_man_println(man, "  - requests per second ("NRS")\n");
  qs_man_println(man, "  - requests within the last minute (req)\n");
  qs_man_println(man, "  - bytes sent to the client per second ("NBS")\n");
  qs_man_println(man, "  - bytes received from the client per second ("NBIS")\n");
  qs_man_println(man, "  - repsonse status codes within the last minute (1xx,2xx,3xx,4xx,5xx)\n");
  qs_man_println(man, "  - average response duration ("NAV")\n");
  qs_man_println(man, "  - average response duration in milliseconds ("NAVMS")\n");
  qs_man_println(man, "  - distribution of response durations within the last minute\n");
  qs_man_print(man, "    (<1s,1s,2s,3s,4s,5s,>5)\n");
  if(man) printf("\n");
  qs_man_println(man, "  - number of established (new) connections within the last minutes (esco)\n");
  qs_man_println(man, "  - average system load (sl)\n");
  qs_man_println(man, "  - free memory (m) (not available for all platforms)\n");
  qs_man_println(man, "  - number of client ip addresses seen withn the last %d seconds (ip)\n", ACTIVE_TIME);
  qs_man_println(man, "  - number of different users seen withn the last %d seconds (usr)\n", ACTIVE_TIME);
  qs_man_println(man, "  - number of events identified by the 'E' format character\n");
  qs_man_println(man, "  - number of mod_qos events within the last minute (qV=create session,\n");
  qs_man_print(man, "    qS=session pass, qD=access denied, qK=connection closed, qT=dynamic\n");
  qs_man_print(man, "    keep-alive, qL=request/response slow down, qs=serialized request)\n");
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
  qs_man_print(man, "     to see the format defintions of the servers access log data.\n");
  if(man) printf("\n");
  qs_man_println(man, "     %s knows the following elements:\n", cmd);
  qs_man_println(man, "     I defines the client ip address (%%h)\n");
  qs_man_println(man, "     R defines the request line (%%r)\n");
  qs_man_println(man, "     S defines HTTP response status code (%%s)\n");
  qs_man_println(man, "     B defines the transferred bytes (%%b or %%O)\n");
  qs_man_println(man, "     i defines the received bytes (%%I)\n");
  qs_man_println(man, "     T defines the request duration (%%T)\n");
  qs_man_println(man, "     t defines the request duration in milliseconds (may be used instead of T)\n");
  qs_man_println(man, "     D defines the request duration in microseconds (may be used instead of T) (%%D)\n");
  qs_man_println(man, "     k defines the number of keepalive requests on the connection (%%k)\n");
  qs_man_println(man, "     U defines the user tracking id (%%{mod_qos_user_id}e)\n");
  qs_man_println(man, "     Q defines the mod_qos_ev event message (%%{mod_qos_ev}e)\n");
  qs_man_println(man, "     C defines the element for the detailed log (-c option), e.g. \"%%U\"\n");
  qs_man_println(man, "     s arbitraty counter to add up (sum within a minute)\n");
  qs_man_println(man, "     a arbitraty counter to build an average from (average per request)\n");
  qs_man_println(man, "     A arbitraty counter to build an average from (average per request)\n");
  qs_man_println(man, "     E comma separated list of event strings\n");
  qs_man_println(man, "     c content type (%%{content-type}o), available in -pc mode only\n");
  qs_man_println(man, "     m request method (GET/POST) (%%m), available in -pc mode only\n");
  qs_man_println(man, "     . defines an element to ignore (unknown string)\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -o <out_file>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifies the file to store the output to.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -p\n");
  if(man) printf("\n");
  qs_man_print(man, "     Used for post processing when reading the log data from a file (cat/pipe).\n");
  qs_man_print(man, "     %s is started using it's offline mode in order to process existing log\n", cmd);
  qs_man_print(man, "     files (post processing).\n");
  qs_man_print(man, "     The option \"-pc\" may be used alternatively if you want to gather request\n");
  qs_man_print(man, "     information per client (identified by IP address (I) or user tracking id (U)\n");
  qs_man_print(man, "     showing how many request each client has performed within the captured period\n");
  qs_man_print(man, "     of time). \"-pc\" supports the format characters IURSBTtDkEcm.\n");
  qs_man_print(man, "     The option \"-pu\" collects statistics on a per URL level (RSTtD).\n");
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
  qs_man_print(man, "     Enables the collection of log statitics for different request types.\n");
  qs_man_print(man, "     'path' specifies the necessary rule file. Each rule consists of a rule\n");
  qs_man_print(man, "     identifier and a regular expression to identify a request seprarated\n");
  qs_man_print(man, "     by a colon, e.g., 01:^(/a)|(/c). The regular expressions are matched against\n");
  qs_man_print(man, "     the log data element which has been identified by the 'C' format character.\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
    printf("Configuration using pipped logging:\n");
    printf("\n");
  } else {
    printf("Example configuration using pipped logging:\n");
  }
  qs_man_println(man, "  LogFormat \"%%t %%h \\\"%%r\\\" %%>s %%b \\\"%%{User-Agent}i\\\" %%T\"\n");
  qs_man_println(man, "  TransferLog \"|/bin/%s -f ..IRSB.T -x -o /var/logs/stat_log\"\n", cmd);
  printf("\n");
  if(man) {
    printf("Configuration using the CustomLog directive:\n");
    printf("\n");
  } else {
   printf("Example configuration using the CustomLog directive:\n");
  }
  qs_man_println(man, "  CustomLog \"|/bin/%s -f ISBTQ -x -o /var/logs/stat_log\" \"%%h %%>s %%b %%T %%{mod_qos_ev}e\"\n", cmd);
  printf("\n");
  if(man) {
    printf("Post processing:\n");
    printf("\n");
  } else {
    printf("Example for post processing:\n");
  }
  qs_man_println(man, "  cat access_log | /bin/%s -f ..IRSB.T -o /var/logs/stat_log -p\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qshead(1), qslogger(1), qspng(1), qsrotate(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://opensource.adnovum.ch/mod_qos/\n");
  } else {
    printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
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
    qerror("could not open file for writing '%s': ", confFile, strerror(errno));
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
  apr_pool_t *pool;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  m_stat_rec = createRec(pool, "", "");

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
        if(strchr(config, 's') || strchr(config, 'a') || strchr(config, 'A')) {
          // enable custom counter
          m_customcounter = 1;
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
    } else if(strcmp(*argv,"-p") == 0) { /* activate offline analysis */
      m_offline = 1;
      qs_set2OfflineMode();
    } else if(strcmp(*argv,"-pc") == 0) { /* activate offline counting analysis */
      m_offline_count = 1;
      qs_set2OfflineMode();
    } else if(strcmp(*argv,"-pu") == 0) { /* activate offline url analysis */
      m_offline_url = 1;
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
    /* init time pattern regex, std apache access log */
    regcomp(&m_trx, 
            "[0-9]{2}/[a-zA-Z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}",
            REG_EXTENDED);
    /* other time patterns: "yyyy mm dd hh:mm:ss,mmm" or "yyyy mm dd hh:mm:ss.mmm" */
    regcomp(&m_trx2, 
            "[0-9]{4}[ -]{1}[0-9]{2}[ -]{1}[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}[,.]{1}[0-9]{3}",
            REG_EXTENDED);
  }

  /*
   * offline url mod
   */
  if(m_offline_url) {
    int i;
    apr_table_entry_t *entry;
    if(nice(10) == -1) {
      fprintf(stderr, "ERROR, failed to change nice value: %s\n", strerror(errno));
    }
    m_url_entries = apr_table_make(pool, MAX_CLIENT_ENTRIES + 1);
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
      fprintf(m_f, "%s;req;%ld;"
              "1xx;%ld;2xx;%ld;3xx;%ld;4xx;%ld;5xx;%ld;"
              NAVMS";%lld;\n",
              entry[i].key,
              url_rec->request_count,
              url_rec->status_1,
              url_rec->status_2,
              url_rec->status_3,
              url_rec->status_4,
              url_rec->status_5,
              url_rec->duration_count_ms / url_rec->request_count);
      
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
    if(nice(10) == -1) {
      fprintf(stderr, "ERROR, failed to change nice value: %s\n", strerror(errno));
    }
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
      long coverage = (client_rec->firstLine * 100 / m_lines);
      long coverageend = 100 - ((client_rec->lastLine * 100) / m_lines);
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
              client_rec->duration / client_rec->request_count,
              client_rec->duration_count_ms / client_rec->request_count,
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
    if(file && m_f != stdout) {
      fclose(m_f);
    }
    return 0;
  }

  /* requires at least an output file and a format string */
  if(file == NULL || config == NULL) usage(cmd, 0);

  if(username && getuid() == 0) {
    struct passwd *pwd = getpwnam(username);
    uid_t uid, gid;
    if(pwd == NULL) {
      qerror("unknown user id '%s': %s", username, strerror(errno));
      exit(1);
    }
    uid = pwd->pw_uid;
    gid = pwd->pw_gid;
    setgid(gid);
    setuid(uid);
    if(getuid() != uid) {
      qerror("setuid failed (%s,%d)", username, uid);
      exit(1);
    }
    if(getgid() != gid) {
      qerror("setgid failed (%d)", gid);
      exit(1);
    }
  }

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

  if(confFile) {
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
   * Offline mode reads an existing file
   * adjusting a virtual clock based on
   * the date string match of the log
   * enties. */
  if(m_offline) {
    if(nice(10) == -1) {
      fprintf(stderr, "ERROR, failed to change nice value: %s\n", strerror(errno));
    }
    fprintf(stderr, "[%s]: offline mode (writes to %s)\n", cmd, file);
    m_date_str[0] = '\0';
    readStdinOffline(pool, config);
    if(!m_verbose) {
      fprintf(stdout, "\n");
    }
  } else {
    /* standard mode reads data from
     * stdin and uses a separate thread
     * to write the data every minute. 
     */
    pthread_create(&tid, tha, loggerThread, NULL);
    readStdin(pool, config);
  }
  fclose(m_f);
  return 0;
}
