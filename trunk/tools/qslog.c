/**
 * Utilities for the quality of service module mod_qos.
 *
 * Real time access log data correlation.
 *
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2007-2010 Pascal Buchbinder
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

static const char revision[] = "$Id: qslog.c,v 2.18 2010-06-16 17:38:55 pbuchbinder Exp $";

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

#include "qs_util.h"

/* ----------------------------------
 * definitions
 * ---------------------------------- */
#define ACTIVE_TIME 600 /* how long is a client "active" (ip addresses seen in the log) */
#define LOG_INTERVAL 60 /* log interval ist 60 sec, don't change this value */

/* ----------------------------------
 * structures
 * ---------------------------------- */

/* ----------------------------------
 * global stat counter
 * ---------------------------------- */
static long m_line_count = 0;
static long long m_byte_count = 0;
static long m_duration_count = 0;
static long m_duration_0 = 0;
static long m_duration_1 = 0;
static long m_duration_2 = 0;
static long m_duration_3 = 0;
static long m_duration_4 = 0;
static long m_duration_5 = 0;
static long m_duration_6 = 0;

static long m_qos_v = 0;
static long m_qos_s = 0;
static long m_qos_d = 0;
static long m_qos_k = 0;
static long m_qos_t = 0;
static long m_qos_l = 0;

static qs_event_t *m_ip_list = NULL;
/* output file */
static FILE *m_f = NULL;
static char  m_file_name[MAX_LINE];
static int   m_rotate = 0;
/* regex to search the time string */
static regex_t m_trx;
/* real time mode (default) or offline */
static int   m_offline = 0;
static char  m_date_str[MAX_LINE];
static int   m_mem = 0;
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
    while(p[0] != delim && p[0] != 0) {
      p++;
    }
  }
  while(p[0] != ' ' && p[0] != 0) {
    p++;
  }
  if(p[0] == ' ') p++;
  return p;
}

/*
 * get and cut an element
 */
static char *cutNext(char **line) {
  char *c = *line;
  char *p = skipElement(*line);
  *line = p;
  p--; p[0] = '\0';
  /* cut leading and tailing " */
  if(c[0] == '\"') {
    c++;
    if(c[strlen(c)-1] == '\"') {
      c[strlen(c)-1] = '\0';
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
#define NAV "av"

/*
 * writes all stat data to the out file
 * an resets all counters
 */
static void printAndResetStat(char *timeStr) {
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
  fprintf(m_f, "%s;"
          NRS";%ld;"
          NBS";%lld;"
          NAV";%ld;"
          "<1s;%ld;"
          "1s;%ld;"
          "2s;%ld;"
          "3s;%ld;"
          "4s;%ld;"
          "5s;%ld;"
          ">5s;%ld;"
	  "ip;%ld;"
	  "qv;%ld;"
	  "qs;%ld;"
	  "qd;%ld;"
	  "qk;%ld;"
	  "qt;%ld;"
	  "ql;%ld;"
	  ,
	  timeStr,
          m_line_count/LOG_INTERVAL,
          m_byte_count/LOG_INTERVAL,
          m_duration_count/(m_line_count == 0 ? 1 : m_line_count),
          m_duration_0,
          m_duration_1,
          m_duration_2,
          m_duration_3,
          m_duration_4,
          m_duration_5,
          m_duration_6,
          qs_countEvent(&m_ip_list),
	  m_qos_v,
	  m_qos_s,
	  m_qos_d,
	  m_qos_k,
	  m_qos_t,
	  m_qos_l
          );
  m_line_count = 0;
  m_byte_count = 0;
  m_duration_count = 0;
  m_duration_0 = 0;
  m_duration_1 = 0;
  m_duration_2 = 0;
  m_duration_3 = 0;
  m_duration_4 = 0;
  m_duration_5 = 0;
  m_duration_6 = 0;
  m_qos_v = 0;
  m_qos_s = 0;
  m_qos_d = 0;
  m_qos_k = 0;
  m_qos_t = 0;
  m_qos_l = 0;
  if(!m_offline) {
    fprintf(m_f, "sl;%.2f;m;%s",
	    av[0], mem[0] ? mem : "-");
  } else {
    fprintf(m_f, "sl;-;m;-");
  }
  fprintf(m_f, "\n");
  qs_csUnLock();
  fflush(m_f);
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
  char *T = NULL; /* time */
  char *B = NULL; /* bytes */
  char *R = NULL; /* request line */
  char *I = NULL; /* client ip */
  char *Q = NULL; /* mod_qos event message */
  const char *c = cstr;
  char *l = line;
  while(c[0]) {
    /* process known types */
    if(strncmp(c, ".", 1) == 0) {
      if(l != NULL && l[0] != '\0') {
        l = skipElement(l);
      }
    } else if(strncmp(c, "T", 1) == 0) {
      if(l != NULL && l[0] != '\0') {
        T = cutNext(&l);
      }
    } else if(strncmp(c, "B", 1) == 0) {
      if(l != NULL && l[0] != '\0') {
        B = cutNext(&l);
      }
    } else if(strncmp(c, "R", 1) == 0) {
      if(l != NULL && l[0] != '\0') {
        R = cutNext(&l);
      }
    } else if(strncmp(c, "I", 1) == 0) {
      if(l != NULL && l[0] != '\0') {
        I = cutNext(&l);
      }
    } else if(strncmp(c, "Q", 1) == 0) {
      if(l != NULL && l[0] != '\0') {
        Q = cutNext(&l);
      }
    } else if(strncmp(c, " ", 1) == 0) {
      /* do nothing */
    } else {
      /* undedined char, skip it */
      if(l != NULL && l[0] != '\0') {
        l++;
      }
    }
    c++;
  }
  if(m_offline && m_verbose) {
    m_lines++;
    printf("[%ld] I=%s B=%s T=%s Q=%s\n", m_lines,
	   I == NULL ? "(null)" : I,
	   B == NULL ? "(null)" : B,
	   T == NULL ? "(null)" : T,
	   Q == NULL ? "(null)" : Q
	   );
  }
  qs_csLock();

  if(Q != NULL) {
    if(strchr(Q, 'V') != NULL) {
      m_qos_v++;
    }
    if(strchr(Q, 'S') != NULL) {
      m_qos_s++;
    }
    if(strchr(Q, 'D') != NULL) {
      m_qos_d++;
    }
    if(strchr(Q, 'K') != NULL) {
      m_qos_k++;
    }
    if(strchr(Q, 'T') != NULL) {
      m_qos_t++;
    }
    if(strchr(Q, 'L') != NULL) {
      m_qos_l++;
    }
  }
  if(I != NULL) {
    /* update/store client IP */
    qs_insertEvent(&m_ip_list, I);
  }
  if(B != NULL) {
    /* transferred bytes */
    m_byte_count = m_byte_count + atoi(B);
  }
  if(T != NULL) {
    /* response duration */
    int tme = atoi(T);
    m_duration_count = m_duration_count + tme;
    if(tme < 1) {
      m_duration_0++;
    } else if(tme == 1) {
      m_duration_1++;
    } else if(tme == 2) {
      m_duration_2++;
    } else if(tme == 3) {
      m_duration_3++;
    } else if(tme == 4) {
      m_duration_4++;
    } else if(tme == 5) {
      m_duration_5++;
    } else {
      m_duration_6++;
    }
  }
  /* request counter */
  m_line_count++;
  qs_csUnLock();
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
    return 0;
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
  fprintf(m_f, "start -----------------\n");
  while(qs_getLine(line, sizeof(line))) {
    time_t l_time = getMinutes(line);
    if(unitTime == 0) {
      unitTime = l_time;
      qs_setTime(unitTime * 60);
    }
    if(unitTime == l_time) {
      updateStat(cstr, line);
    } if(l_time < unitTime) {
      /* leap in time... */
      updateStat(cstr, line);
    } else {
      if(!m_verbose) {
	fprintf(stdout, ".");
	fflush(stdout);
      }
      while(l_time > unitTime) {
	snprintf(buf, sizeof(buf), "%s %.2ld:%.2ld:00", m_date_str, unitTime/60, unitTime%60);
	printAndResetStat(buf);
	unitTime++;
	qs_setTime(unitTime * 60);;
      }
      updateStat(cstr, line);
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
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", ptr);
	snprintf(arch, sizeof(arch), "%s.%s", m_file_name, buf);
	if(fclose(m_f) != 0) {
	  qerror("failed to close file '%s': %s", m_file_name, strerror(errno));
	}
	if(rename(m_file_name, arch) != 0) {
	  qerror("failed to move file '%s': %s", arch, strerror(errno));
	}
	m_f = fopen(m_file_name, "a+"); 
      }
    }
  }
}

static void usage(char *cmd) {
  printf("\n");
  printf("Utility to collect request statistics from access log data.\n");
  printf("\n");
  printf("Usage: %s -f <format_string> -o <out_file> [-p [-v]] [-x] [-u <name>] [-m]\n", cmd);
  printf("\n");
  printf("Summary\n");
  printf("%s is a real time access log analyzer. It collects\n", cmd);
  printf("the data from stdin. The output is written to the specified\n");
  printf("file every minute. The output includes the following entries:\n");
  printf("  - requests per second ("NRS")\n");
  printf("  - bytes (http body data) sent to the client per second ("NBS")\n");
  printf("  - average response duration ("NAV")\n");
  printf("  - distribution of response durations within the last minute\n");
  printf("    (<1s,1s,2s,3s,4s,5s,>5)\n");
  printf("  - average system load (sl)\n");
  printf("  - free memory (m) (not available for all platforms)\n");
  printf("  - number of client ip addresses seen withn the last %d seconds (ip)\n", ACTIVE_TIME);
  printf("  - number of mod_qos events within the last minute (qv=create session,\n");
  printf("    qs=session pass, qd=access denied, qk=connection closed, qt=dynamic\n");
  printf("    keep-alive, ql=request/response slow down)\n");
  printf("\n");
  printf("Options\n");
  printf("  -f <format_string>\n");
  printf("     Defines the log data format and the positions of data\n");
  printf("     elements processed by this utility.\n");
  printf("     See to the 'LogFormat' directive of the httpd.conf file\n");
  printf("     to see the format defintions of the servers access log\n");
  printf("     data. %s knows the following elements:\n", cmd);
  printf("     T defines the request duration (%%T)\n");
  printf("     B defines the transferred bytes (%%b)\n");
  printf("     R defines the request line (%%r)\n");
  printf("     I defines the client ip address (%%h)\n");
  printf("     Q defines the mod_qos_ev event message (%%{mod_qos_ev}o)\n");
  printf("     . defines an element to ignore (unknown string)\n");
  printf("  -o <out_file>\n");
  printf("     Specifies the file to store the output to.\n");
  printf("  -p\n");
  printf("     Used when reading the log data from a file (cat/pipe). %s is\n", cmd);
  printf("     started using it's offline mode in order to process existing log\n");
  printf("     files (post processing).\n");
  printf("  -v\n");
  printf("     Verbose mode.\n");
  printf("  -x\n");
  printf("     Rotates the output file once a day (move).\n");
  printf("  -u <name>\n");
  printf("     Become another user, e.g. nobody.\n");
  printf("  -m\n");
  printf("     Calculates free system memory every minute.\n");
  printf("\n");
  printf("Example configuration using pipped logging:\n");
  printf("  LogFormat \"%%t %%h \\\"%%r\\\" %%>s %%b \\\"%%{User-Agent}i\\\" %%T\"\n");
  printf("  TransferLog \"|./bin/%s -f ..IR.B.T -o ./logs/stat_log\"\n", cmd);
  printf("\n");
  printf("Example for post processing:\n");
  printf("  cat access_log | ./bin/%s -f ..IR.B.T -o ./logs/stat_log -p\n", cmd);
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  exit(1);
}

int main(int argc, char **argv) {
  char *config = NULL;
  char *file = NULL;
  char *cmd = strrchr(argv[0], '/');
  char *username = NULL;
  pthread_attr_t *tha = NULL;
  pthread_t tid;
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
      }
    } else if(strcmp(*argv,"-o") == 0) { /* this is the out file */
      if (--argc >= 1) {
	file = *(++argv);
      }
    } else if(strcmp(*argv,"-u") == 0) { /* switch user id */
      if (--argc >= 1) {
	username = *(++argv);
      }
    } else if(strcmp(*argv,"-p") == 0) { /* activate offline analysis */
      m_offline = 1;
      qs_set2OfflineMode();
    } else if(strcmp(*argv,"-m") == 0) { /* activate memory usage */
      m_mem = 1;
    } else if(strcmp(*argv,"-v") == 0) {
      m_verbose = 1;
    } else if(strcmp(*argv,"-x") == 0) { /* activate log rotation */
      m_rotate = 1;
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd);
    } else {
      qerror("unknown option '%s'", *argv);
      exit(1);
    }
    argc--;
    argv++;
  }
  /* requires at leas an output file and a format string */
  if(file == NULL || config == NULL) usage(cmd);

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
    qerror("could not open file for writing '%s': ", file, strerror(errno));
    exit(1);
  }
  if(strlen(file) > (sizeof(m_file_name) - strlen(".yyyymmddHHMMSS "))) {
    qerror("file name too long '%s'", file);
    exit(1);
  }
  strcpy(m_file_name, file);

  if(m_offline) {
    nice(10);
    /* init time pattern regex */
    regcomp(&m_trx, "[0-9]{2}/[a-zA-Z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}", REG_EXTENDED);
    fprintf(stderr, "[%s]: offline mode (writes to %s)\n", cmd, file);
    m_date_str[0] = '\0';
    readStdinOffline(config);
    fprintf(stdout, "\n");
  } else {
    pthread_create(&tid, tha, loggerThread, NULL);
    readStdin(config);
  }
  fclose(m_f);
  return 0;
}

