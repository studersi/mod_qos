/**
 * Utilities for the quality of service module mod_qos.
 *
 * Real time access log data correlation.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2012 Pascal Buchbinder
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

static const char revision[] = "$Id: qslog.c,v 1.36 2012-01-26 21:18:32 pbuchbinder Exp $";

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>

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

#include "qs_util.h"

/* ----------------------------------
 * definitions
 * ---------------------------------- */
#define ACTIVE_TIME 600 /* how long is a client "active" (ip addresses seen in the log) */
#define LOG_INTERVAL 60 /* log interval ist 60 sec, don't change this value */
#define LOG_DET ".detailed"
#define RULE_DELIM ':'
#define MAX_CLIENT_ENTRIES 25000

/* ----------------------------------
 * structures
 * ---------------------------------- */

typedef struct {
  long request_count;
  long error_count;
  long long duration;
  long status_1;
  long status_2;
  long status_3;
  long status_4;
  long status_5;
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
  long duration_count;
  long duration_0;
  long duration_1;
  long duration_2;
  long duration_3;
  long duration_4;
  long duration_5;
  long duration_6;
  long connections;
  
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
/* regex to search the time string */
static regex_t m_trx;
static regex_t m_trx2;
/* real time mode (default) or offline */
static int   m_offline = 0;
static int   m_offline_data = 0;
static char  m_date_str[MAX_LINE];
static int   m_mem = 0;
static apr_table_t *m_client_entries = NULL;
static int   m_max_client_entries = 0;
static int   m_offline_count = 0;
/* debug */
static long  m_lines = 0;
static int   m_verbose = 0;

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
 * skip an element to the next space
 */
static char *skipElement(const char* line) {
  char *p = (char *)line;
  /* check for quotes (double or single) */
  char delim = p[0];
  if(delim == '\'' || delim == '\"') {
    p++;
    while(p[0] != delim && p[0] != 0 && p[-1] != '\\') {
      p++;
    }
    p++;
  } else {
    char *eq = NULL;
    if(m_offline || m_offline_count) {
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

static void stripNum(char **p) {
  char *s = *p;
  int len;
  while(s && (s[0] < '0' || s[0] > '9')) {
    s++;
  }
  len = strlen(s);
  while(len > 0 && (s[len] < '0' || s[len] > '9')) {
    s[len] = '\0';
    len--;
  }
  *p = s;
}

/*
 * get and cut an element
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
      int rc;
      char command[1024];
      char outfile[1024];
      snprintf(outfile, sizeof(outfile), "/tmp/qslog.%d", getpid());
      snprintf(command, sizeof(command), "%s 1 2 1>%s", vmstat, outfile);
      rc = system(command);
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

static void printStat2File(FILE *f, char *timeStr, stat_rec_t *stat_rec, int offline, int main,
			   double *av, const char *mem) {
  char bis[256];
  char esco[256];
  char ip[256];
  char usr[256];
  bis[0] = '\0';
  esco[0] = '\0';
  if(stat_rec->i_byte_count != -1) {
    sprintf(bis, NBIS";%lld;", stat_rec->i_byte_count/LOG_INTERVAL);
  }
  if(main && stat_rec->connections != -1) {
    sprintf(esco, "esco;%ld;", stat_rec->connections);
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
          NAV";%ld;"
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
	  stat_rec->qos_ser
          );
  stat_rec->line_count = 0;
  stat_rec->byte_count = 0;
  if(stat_rec->i_byte_count != -1) {
    stat_rec->i_byte_count = 0;
  }
  if(main && (stat_rec->connections != -1)) {
    stat_rec->connections = 0;
  }
  stat_rec->status_1 = 0;
  stat_rec->status_2 = 0;
  stat_rec->status_3 = 0;
  stat_rec->status_4 = 0;
  stat_rec->status_5 = 0;
  stat_rec->duration_count = 0;
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
      fprintf(f, "sl;%.2f;m;%s",
	      av[0], mem[0] ? mem : "-");
    } else {
      fprintf(f, "sl;-;m;-");
      m_offline_data = 0;
    }
  }
  fprintf(f, "\n");
}

static stat_rec_t *createRec(const char *id, const char *pattern) {
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
  rec->duration_0 = 0;
  rec->duration_1 = 0;
  rec->duration_2 = 0;
  rec->duration_3 = 0;
  rec->duration_4 = 0;
  rec->duration_5 = 0;
  rec->duration_6 = 0;
  rec->connections = -1;

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
  return rec;
}

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

/*
 * writes all stat data to the out file
 * an resets all counters
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

static void updateClient(stat_rec_t *rec, char *T, char *t, char *D, char *S,
			 char *BI, char *B, char *R, char *I, char *U, char *Q, char *k, char *C,
			 long tme) {
  long long start;
  long long end;
  struct timeval tv;
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
    client_rec->duration = 0;
    client_rec->status_1 = 0;
    client_rec->status_2 = 0;
    client_rec->status_3 = 0;
    client_rec->status_4 = 0;
    client_rec->status_5 = 0;
    apr_table_setn(m_client_entries, tid, (char *)client_rec);
  }
  client_rec->request_count++;
  client_rec->duration += tme;
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
    } else if(S[0] == '4') {
      client_rec->status_4++;
    } else if(S[0] == '5') {
      client_rec->status_5++;
    }
  }
  return;
}

static void updateRec(stat_rec_t *rec, char *T, char *t, char *D, char *S,
		      char *BI, char *B, char *R, char *I, char *U, char *Q, char *k, char *C,
		      long tme) {
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
static void updateStat(const char *cstr, char *line) {
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
  const char *c = cstr;
  char *l = line;
  long tme;
  if(!line[0]) return;
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
    } else if(c[0] == ' ') {
      /* do nothing */
    } else {
      /* undedined char, skip it */
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
  tme = 0;
  if(T != NULL || t != NULL || D != NULL) {
    /* response duration */
    if(T) {
      stripNum(&T);
      tme = atol(T);
    } else if(t) {
      stripNum(&t);
      tme = atol(t) / 1000;
    } else if(D) {
      stripNum(&D);
      tme = atol(D) / 1000000;
    }
  }
  updateRec(m_stat_rec, T, t, D, S, BI, B, R, I, U, Q, k, C, tme);
  if(rec) {
    updateRec(rec, T, t, D, S, BI, B, R, I, U, Q, k, C, tme);
  }
  if(m_offline_count) {
    updateClient(NULL, T, t, D, S, BI, B, R, I, U, Q, k, C, tme);
  }
  qs_csUnLock();

  if(m_verbose && (m_offline || m_offline_count)) {
    m_lines++;
    printf("[%ld] I=[%s] U=[%s] B=[%s] i=[%s] S=[%s] T=[%ld] Q=[%s]\n", m_lines,
	   I == NULL ? "(null)" : I,
	   U == NULL ? "(null)" : U,
	   B == NULL ? "(null)" : B,
	   BI == NULL ? "(null)" : BI,
	   S == NULL ? "(null)" : S,
	   tme,
	   Q == NULL ? "(null)" : Q
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
static void readStdin(const char *cstr) {
  char line[MAX_LINE];
  while(qs_getLine(line, sizeof(line))) {
    updateStat(cstr, line);
  }
}

/*
 * reads from stdin and calls updateStat()
 * and printAndResetStat()
 * processes the time information from the
 * access log lines
 * => used for offline analysis
 */
static void readStdinOffline(const char *cstr) {
  char line[MAX_LINE];
  char buf[32];
  time_t unitTime = 0;
  while(qs_getLine(line, sizeof(line))) {
    time_t l_time = getMinutes(line);
    m_offline_data = 1;
    if(unitTime == 0) {
      unitTime = l_time;
      qs_setTime(unitTime * 60);
    }
    if(unitTime == l_time) {
      updateStat(cstr, line);
    } if(l_time < unitTime) {
      /* leap in time... */
      updateStat(cstr, line);
      fprintf(stdout, "X");
      fflush(stdout);
      unitTime = 0;
    } else {
      if(l_time > unitTime) {
      	if(!m_verbose) {
	  fprintf(stdout, ".");
	  fflush(stdout);
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
      updateStat(cstr, line);
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
	m_f = fopen(m_file_name, "a+"); 
	if(m_f2) {
	  fclose(m_f2);
	  rename(m_file_name2, arch2);
	  m_f2 = fopen(m_file_name2, "a+"); 
	}
      }
    }
  }
  return NULL;
}

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
  qs_man_print(man, "%s%s -f <format_string> -o <out_file> [-p [-v]] [-x] [-u <name>] [-m] [-c <path>]\n", man ? "" : "Usage: ", cmd);
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
  qs_man_println(man, "  - bytes sent to the client per second ("NBS")\n");
  qs_man_println(man, "  - bytes received from the client per second ("NBIS")\n");
  qs_man_println(man, "  - repsonse status codes within the last minute (1xx,2xx,3xx,4xx,5xx)\n");
  qs_man_println(man, "  - average response duration ("NAV")\n");
  qs_man_println(man, "  - distribution of response durations within the last minute\n");
  qs_man_print(man, "    (<1s,1s,2s,3s,4s,5s,>5)\n");
  if(man) printf("\n");
  qs_man_println(man, "  - number of established (new) connections within the last minutes (esco)\n");
  qs_man_println(man, "  - average system load (sl)\n");
  qs_man_println(man, "  - free memory (m) (not available for all platforms)\n");
  qs_man_println(man, "  - number of client ip addresses seen withn the last %d seconds (ip)\n", ACTIVE_TIME);
  qs_man_println(man, "  - number of different users seen withn the last %d seconds (usr)\n", ACTIVE_TIME);
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
  qs_man_println(man, "     t defines the request duration in milliseconds (optionally used instead of T)\n");
  qs_man_println(man, "     D defines the request duration in microseconds (optionally used instead of T) (%%D)\n");
  qs_man_println(man, "     k defines the number of keepalive requests on the connection (%%k)\n");
  qs_man_println(man, "     U defines the user tracking id (%%{mod_qos_user_id}e)\n");
  qs_man_println(man, "     Q defines the mod_qos_ev event message (%%{mod_qos_ev}e)\n");
  qs_man_println(man, "     C defines the element for the detailed log (-c option), e.g. \"%%U\"\n");
  qs_man_println(man, "     . defines an element to ignore (unknown string)\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -o <out_file>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifies the file to store the output to.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -p\n");
  if(man) printf("\n");
  qs_man_print(man, "     Used when reading the log data from a file (cat/pipe). %s is\n", cmd);
  qs_man_print(man, "     started using it's offline mode in order to process existing log\n");
  qs_man_print(man, "     files (post processing).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -v\n");
  if(man) printf("\n");
  qs_man_print(man, "     Verbose mode.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -x\n");
  if(man) printf("\n");
  qs_man_print(man, "     Rotates the output file once a day (move).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -u <name>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Become another user, e.g. www-data.\n");
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
  qs_man_println(man, "  TransferLog \"|./bin/%s -f ..IRSB.T -x -o ./logs/stat_log\"\n", cmd);
  printf("\n");
  if(man) {
    printf("Configuration using the CustomLog directive:\n");
    printf("\n");
  } else {
   printf("Example configuration using the CustomLog directive:\n");
  }
  qs_man_println(man, "  CustomLog \"|./bin/%s -f ISBTQ -x -o ./logs/stat_log\" \"%%h %%>s %%b %%T %%{mod_qos_ev}e\"\n", cmd);
  printf("\n");
  if(man) {
    printf("Post processing:\n");
    printf("\n");
  } else {
    printf("Example for post processing:\n");
  }
  qs_man_println(man, "  cat access_log | ./bin/%s -f ..IRSB.T -o ./logs/stat_log -p\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsexec(1), qsfilter2(1), qsgrep(1), qspng(1), qsrotate(1), qssign(1), qstail(1)\n");
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

static stat_rec_t *loadRule(const char *confFile) {
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
      next = createRec(id, p);
      if(rec == NULL) {
	rec = next;
      }
      if(prev) {
	prev->next = next;
      } else {
	rec->next = next;
      }
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
  m_stat_rec = createRec("", "");

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
    } else if(strcmp(*argv,"-m") == 0) { /* activate memory usage */
      m_mem = 1;
    } else if(strcmp(*argv,"-v") == 0) {
      m_verbose = 1;
    } else if(strcmp(*argv,"-x") == 0) { /* activate log rotation */
      m_rotate = 1;
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

  if(m_offline || m_offline_count) {
    /* init time pattern regex, std apache access log */
    regcomp(&m_trx, 
	    "[0-9]{2}/[a-zA-Z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}",
	    REG_EXTENDED);
    /* other time patterns: "yyyy mm dd hh:mm:ss,mmm" or "yyyy mm dd hh:mm:ss.mmm" */
    regcomp(&m_trx2, 
	    "[0-9]{4}[ -]{1}[0-9]{2}[ -]{1}[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}[,.]{1}[0-9]{3}",
	    REG_EXTENDED);
  }

  if(m_offline_count) {
    int i;
    apr_table_entry_t *entry;
    apr_pool_t *pool;
    int rc = nice(10);
    if(config == NULL) usage(cmd, 0);
    apr_app_initialize(&argc, &argv, NULL);
    apr_pool_create(&pool, NULL);
    m_client_entries = apr_table_make(pool, MAX_CLIENT_ENTRIES);
    readStdinOffline(config);
    fprintf(stdout, ".\n");
    entry = (apr_table_entry_t *) apr_table_elts(m_client_entries)->elts;
    for(i = 0; i < apr_table_elts(m_client_entries)->nelts; i++) {
      client_rec_t *client_rec = (client_rec_t *)entry[i].val;
      printf("%s;req;%ld;errors;%ld;av;%lld;1xx;%ld;2xx;%ld;3xx;%ld;4xx;%ld;5xx;%ld\n",
	     entry[i].key,
	     client_rec->request_count,
	     client_rec->error_count,
	     client_rec->duration / client_rec->request_count,
	     client_rec->status_1,
	     client_rec->status_2,
	     client_rec->status_3,
	     client_rec->status_4,
	     client_rec->status_5);

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
    m_stat_sub = loadRule(confFile);
    m_f2 = fopen(m_file_name2, "a+");
    if(m_f == NULL) {
      qerror("could not open file for writing '%s': %s", m_file_name2, strerror(errno));
      exit(1);
    }
  }

  if(m_offline) {
    int rc = nice(10);
    fprintf(stderr, "[%s]: offline mode (writes to %s)\n", cmd, file);
    m_date_str[0] = '\0';
    readStdinOffline(config);
    if(!m_verbose) {
      fprintf(stdout, "\n");
    }
  } else {
    pthread_create(&tid, tha, loggerThread, NULL);
    readStdin(config);
  }
  fclose(m_f);
  return 0;
}
