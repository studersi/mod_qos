/**
 * Utilities for the quality of service module mod_qos.
 *
 * Log data signing tool to ensure data integrity.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2010-2011 Pascal Buchbinder
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

static const char revision[] = "$Id: qssign.c,v 1.17 2011-09-02 06:36:49 pbuchbinder Exp $";

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <signal.h>

//#include <config.h>

/* openssl */
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* apr/apr-util */
#include <apr.h>
#include <apr_base64.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>
#include <apr_file_io.h>
#include <apr_time.h>

#define MAX_LINE 65536
#define CR 13
#define LF 10
#define SEQDIG "12"
#define MAX_STRING_LEN 32768

#define QS_END "qssign---end-of-data"

static const char *m_fmt = "";
static long m_nr = 1;
static int  m_logend = 0;
static void (*m_end)(const char *) = NULL;
static int m_end_pos = 0;
static const char *m_sec = NULL;

typedef struct {
  const char* fmt;
  const char* pattern;
  const char* test;
} qos_p_t;

#define severity "[A-Z]+"

static const qos_p_t pattern[] = {
  {
    "%s | INFO  | "QS_END,
    "^[0-9]{4}[-][0-9]{2}[-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}[ ]+[|][ ]+"severity"[ ]+[|][ ]+[a-zA-Z0-9]+",
    "2010-04-14 20:18:37,464 | INFO  | org.hibernate.cfg.Configuration"
  },
  {
    "%s INFO  "QS_END,
    "^[0-9]{4}[-][0-9]{2}[-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}[ ]+"severity"[ ]+",
    "2011-08-30 07:27:22,738 INFO  loginId='test'"
  },
  {
    "%s qssign          end                                      INFO  "QS_END,
    "^[0-9]{4}[-][0-9]{2}[-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}[ ]+[a-zA-Z0-9\\.-]+[ ]+[a-zA-Z0-9\\.-]+[ ]+"severity"[ ]+",
    "2011-09-01 07:37:17,275 main            org.apache.catalina.startup.Catalina     INFO  Server"
  },
  {
    "%s INFO  "QS_END,
    "^[0-9]{4}[-][0-9]{2}[-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}[ ]+",
    "2011-08-30 07:27:22,738 "
  },
  { NULL, NULL, NULL }
};

static int qs_getLine(char *s, int n) {
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

static void qs_write(char *line, int line_size, const char *sec, int sec_len) {
  HMAC_CTX ctx;
  unsigned char data[HMAC_MAX_MD_CBLOCK];
  unsigned int len;
  char *m;
  int data_len;
  sprintf(&line[strlen(line)], " %."SEQDIG"ld", m_nr);
  HMAC_Init(&ctx, sec, sec_len, EVP_sha1());
  HMAC_Update(&ctx, (const unsigned char *)line, strlen(line));
  HMAC_Final(&ctx, data, &len);
  m = calloc(1, apr_base64_encode_len(len) + 1);
  data_len = apr_base64_encode(m, (char *)data, len);
  m[data_len] = '\0';
  printf("%s#%s\n", line, m);
  fflush(stdout);
  free(m);
  m_nr++;
  return;
}

/*
 * [Fri Dec 03 07:37:40 2010] [notice] .........
 */
static void qs_end_apache_err(const char *sec) {
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  char time_string[1024];
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  strftime(time_string, sizeof(time_string), "%a %b %d %H:%M:%S %Y", ptr);
  sprintf(line, "[%s] [notice] "QS_END, time_string);
  qs_write(line, line_size, sec, sec_len);
  return;
}

/*
 * 12.12.12.12 - - [03/Dec/2010:07:36:51 +0100] ...............
 */
static void qs_end_apache_acc(const char *sec) {
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  char time_string[1024];
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  char sign;
  int timz;
  apr_time_exp_t xt;
  apr_time_exp_lt(&xt, apr_time_now());
  timz = xt.tm_gmtoff;
  if(timz < 0) {
    timz = -timz;
    sign = '-';
  } else {
    sign = '+';
  }
  strftime(time_string, sizeof(time_string), "%d/%b/%Y:%H:%M:%S", ptr);
  sprintf(line, "0.0.0.0 - - [%s %c%.2d%.2d] "QS_END, time_string, sign, timz / (60*60), (timz % (60*60)) / 60);
  qs_write(line, line_size, sec, sec_len);
  return;
}

/*
 * 2010 12 03 17:00:30.425 qssign     end        0.0              5-NOTICE:  ..............
 */
static void qs_end_nj(const char *sec) {
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  char time_string[1024];
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  char buf[1024];
  int i;
  for(i = 0; i < m_end_pos; i++) {
    buf[i] = ' ';
  }
  buf[i] = '\0';
  strftime(time_string, sizeof(time_string), "%Y %m %d %H:%M:%S.000", ptr);
  sprintf(line, "%s qssign     end        0.0%s 5-NOTICE:  "QS_END, time_string, buf);
  qs_write(line, line_size, sec, sec_len);
  return;
}

/* 2010-04-14 20:18:37,464 ... (using m_fmt) */
static void qs_end_lj(const char *sec) {
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  char time_string[1024];
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S,000", ptr);
  sprintf(line, m_fmt, time_string);
  qs_write(line, line_size, sec, sec_len);
  return;
}

/* Dec  6 04:00:06 localhost kernel: */
static void qs_end_lx(const char *sec) {
  char hostname[1024];
  int len = sizeof(hostname);
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  char time_string[1024];
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  strftime(time_string, sizeof(time_string), "%b %e %H:%M:%S", ptr);
  if(gethostname(hostname, len) != 0) {
    hostname[0] = '-';
    hostname[1] = '\0';
  }
  sprintf(line, "%s %s qssign: "QS_END, time_string, hostname);
  qs_write(line, line_size, sec, sec_len);
  return;
}

void qs_signal_exit(int e) {
  if(m_logend && (m_end != NULL)) {
    m_end(m_sec);
  }
  exit(0);
}

/*
 * known pattern
 * - [Fri Dec 03 07:37:40 2010] [notice] .........
 * - 12.12.12.12 - - [03/Dec/2010:07:36:51 +0100] ...............
 * - 2010 12 03 17:00:30.425 qssign     end        0.0              5-NOTICE:  ..............
 *                                                 46  <- var ->    63      71
 * - Dec  6 04:00:06 localhost kernel:
 * - some 2010-12-03 17:00:30,425 ...
 */
static void qs_set_format(char *s) {
  regex_t r_apache_err; 
  regex_t r_apache_acc;
  regex_t r_nj;
  regex_t r_lx;
  if(regcomp(&r_apache_err,
	     "^\\[[a-zA-Z]{3} [a-zA-Z]{3} [0-9]+ [0-9]+:[0-9]+:[0-9]+ [0-9]+\\] \\[[a-zA-Z]+\\] ",
	     REG_EXTENDED) != 0) {
    fprintf(stderr, "failed to compile regex (err)\n");
    exit(1);
  }
  if(regcomp(&r_apache_acc,
	     "^[0-9.]+ [a-zA-Z0-9\\@_\\.\\-]+ [a-zA-Z0-9\\@_\\.\\-]+ \\[[0-9]+/[a-zA-Z]{3}/[0-9:]+[0-9\\+ ]+\\] ",
	     REG_EXTENDED) != 0) {
    fprintf(stderr, "failed to compile regex (acc)\n");
    exit(1);
  }
  if(regcomp(&r_nj,
	     "^[0-9]{4} [0-9]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3} [a-zA-Z0-9]+[ ]+.*[A-Z]+[ ]*:",
	     REG_EXTENDED) != 0) {
    fprintf(stderr, "failed to compile regex (nj)\n");
    exit(1);
  }
  if(regcomp(&r_lx,
	     "^[a-zA-Z]{3}[ ]+[0-9]+[ ]+[0-9]{2}:[0-9]{2}:[0-9]{2}[ ]+[a-zA-Z0-9_\\.\\-]+[ ]+[a-zA-Z0-9_\\.\\-]+:",
	     REG_EXTENDED) != 0) {
    fprintf(stderr, "failed to compile regex (lx)\n");
    exit(1);
  }
  if(regexec(&r_apache_err, s, 0, NULL, 0) == 0) {
    m_end = &qs_end_apache_err;
  } else if(regexec(&r_apache_acc, s, 0, NULL, 0) == 0) {
    m_end = &qs_end_apache_acc;
  } else if(regexec(&r_nj, s, 0, NULL, 0) == 0) {
    char *dp = strstr(s, ": ");
    if(dp) {
      /* calculate the "var" size, see comment above */
      m_end_pos = dp - s - 47 - 8 - 3;
      if((m_end_pos < 0) || (m_end_pos > 1000)) {
	m_end_pos = 0;
      }
    }
    m_end = &qs_end_nj;
  } else if(regexec(&r_lx, s, 0, NULL, 0) == 0) {
    m_end = &qs_end_lx;    
  }
  // search within the generic yyyy-mm-dd hh-mm-ss,mmm patterns
  if(!m_end) {
    const qos_p_t *p = pattern;
    while(p->fmt) {
      regex_t r_j;
      if(regcomp(&r_j, p->pattern, REG_EXTENDED) != 0) {
	fprintf(stderr, "failed to compile regex (%s)\n", p->pattern);
	exit(1);
      }
      if(regexec(&r_j, s, 0, NULL, 0) == 0) {
	m_fmt = p->fmt;
	m_end = &qs_end_lj;      
	break;
      }
      p++;
    }
  }
  /* default (apache error log format) */
  if(m_end == NULL) {
    m_end = &qs_end_apache_err;
  }
  return;
}

static void qs_sign(const char *sec) {
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  while(qs_getLine(line, line_size)) {
    if(m_logend && (m_end == NULL)) {
      qs_set_format(line);
    }
    qs_write(line, line_size, sec, sec_len);
  }
  return;
}

static long qs_verify(const char *sec) {
  int end_seen = 0;
  int sec_len = strlen(sec);
  long err = 0; // errors
  long lnr = 0; // line number
  char line[MAX_LINE];
  int line_size = sizeof(line);
  m_nr = -1; // sequence number
  while(qs_getLine(line, line_size)) {
    int valid = 0;
    long ns = 0;
    HMAC_CTX ctx;
    unsigned char data[HMAC_MAX_MD_CBLOCK];
    unsigned int len;
    char *m;
    int data_len;
    char *sig = strrchr(line, '#');
    char *seq = strrchr(line, ' ');
    lnr++;
    if(seq && sig) {
      sig[0] = '\0';
      sig++;
      /* verify hmac */
      HMAC_Init(&ctx, sec, sec_len, EVP_sha1());
      HMAC_Update(&ctx, (const unsigned char *)line, strlen(line));
      HMAC_Final(&ctx, data, &len);
      m = calloc(1, apr_base64_encode_len(len) + 1);
      data_len = apr_base64_encode(m, (char *)data, len);
      m[data_len] = '\0';
      if(strcmp(m, sig) != 0) {
	err++;
	fprintf(stderr, "ERROR on line %ld: invalid signature\n", lnr);
      } else {
	valid = 1;
      }
      free(m);
      /* verify sequence */
      seq++;
      ns = atol(seq);
      if(ns == 0) {
	err++;
	fprintf(stderr, "ERROR on line %ld: invalid sequence\n", lnr);
      } else {
	if(m_nr != -1) {
	  if(m_nr != ns) {
	    if(ns == 1) {
	      if(!end_seen) {
		err++;
		fprintf(stderr, "ERROR on line %ld: wrong sequence, server restart? (expect %."SEQDIG"ld)\n",
			lnr, m_nr);
	      }
	    } else {
	      err++;
	      fprintf(stderr, "ERROR on line %ld: wrong sequence (expect %."SEQDIG"ld)\n", lnr, m_nr);
	    }
	  }
	} else if(m_logend) {
	  // log should (if not rotated) with message 0
	  if(ns != 1) {
	    fprintf(stderr, "NOTICE: log starts with sequence %."SEQDIG"ld, log rotation?"
		    " (expect %."SEQDIG"d)\n", ns, 1);
	  }
	}
	if(valid) {
	  m_nr = ns;
	}
      }
    } else {
      err++;
      fprintf(stderr, "ERROR on line %ld: missing signature/sequence\n", lnr);
    }
    end_seen = 0;
    if(valid) {
      char *end_marker = strstr(line, QS_END);
      m_nr++;
      if(end_marker != NULL) {
	/* QS_END + " " + SEQDIG */
	int sz = strlen(QS_END) + 1 + atoi(SEQDIG);
	if(sz == (strlen(line) - (end_marker - line))) {
	  end_seen = 1;
	}
      }
    }
  }
  if(m_logend && !end_seen) {
    fprintf(stderr, "NOTICE: no end marker seen, log rotation? (expect %."SEQDIG"ld)\n", m_nr);
  }
  return err;
}

static void qs_failedexec(const char *msg, const char *cmd, apr_status_t status) {
  char buf[MAX_STRING_LEN];
  apr_strerror(status, buf, sizeof(buf));
  fprintf(stderr, "ERROR %s '%s': '%s'\n", msg, cmd, buf);
  exit(1);
}

static apr_table_t *qs_args(apr_pool_t *pool, const char *line) {
  char *last = apr_pstrdup(pool, line);
  apr_table_t* table = apr_table_make(pool, 10);
  char *val;
  while((val = apr_strtok(NULL, " ", &last))) {
    apr_table_addn(table, val, "");
  }
  return table;
}

static char *qs_readpwd(apr_pool_t *pool, const char *prg) {
  apr_status_t status;
  apr_proc_t proc;
  const char **args;
  apr_table_entry_t *entry;
  char *last;
  char *copy = apr_pstrdup(pool, prg);
  char *cmd = apr_strtok(copy, " ", &last);
  apr_table_t *a = qs_args(pool, prg);
  int i;
  apr_procattr_t *attr;
  apr_size_t len = MAX_STRING_LEN;
  char *buf = apr_pcalloc(pool, len);

  args = apr_pcalloc(pool, (apr_table_elts(a)->nelts + 1) * sizeof(const char *));
  entry = (apr_table_entry_t *) apr_table_elts(a)->elts;
  for(i = 0; i < apr_table_elts(a)->nelts; i++) {
    args[i] = entry[i].key;
  }
  args[i] = NULL;

  if((status = apr_procattr_create(&attr, pool)) != APR_SUCCESS) {
    qs_failedexec("while reading password from executable", prg, status);
  }
  if((status = apr_procattr_cmdtype_set(attr, APR_PROGRAM_PATH)) != APR_SUCCESS) {
    qs_failedexec("while reading password from executable", prg, status);
  }
  if((status = apr_procattr_detach_set(attr, 0)) != APR_SUCCESS) {
    qs_failedexec("while reading password from executable", prg, status);
  }
  if((status = apr_procattr_io_set(attr, APR_FULL_BLOCK, APR_FULL_BLOCK, APR_NO_PIPE)) != APR_SUCCESS) {
    qs_failedexec("while reading password from executable", prg, status);
  }
  if((status = apr_proc_create(&proc, cmd, args, NULL, attr, pool)) != APR_SUCCESS) {
    qs_failedexec("could not execute program", prg, status);
  } else {
    char *e;
    status = apr_proc_wait(&proc, NULL, NULL, APR_WAIT);
    if(status != APR_CHILD_DONE && status != APR_SUCCESS) {
      qs_failedexec("while reading password from executable", prg, status);
    }
    status = apr_file_read(proc.out, buf, &len);
    if(status != APR_SUCCESS) {
      qs_failedexec("failed to read password from program", prg, status);
    }
    e = buf;
    while(e && e[0]) {
      if((e[0] == LF) || (e[0] == CR)) {
	e[0] = '\0';
      } else {
	e++;
      }
    }
  }
  return buf;
}

static void usage(char *cmd) {
  printf("\n");
  printf("Utility to sign/verify log data.\n");
  printf("\n");
  printf("Usage: %s -s|S <secret> [-e] [-v]\n", cmd);
  printf("\n");
  printf("Summary\n");
  printf("%s is a log data integrity check tool. It reads log data\n", cmd);
  printf("from stdin (pipe) and writes the signed data to stdout.\n");
  printf("\n");
  printf("Options\n");
  printf("  -s <secret>\n");
  printf("     Passphrase used to calculate signature.\n");
  printf("  -S <program>\n");
  printf("     Specifies a program which writes the passphrase to stdout.\n");
  printf("  -e\n");
  printf("     Writes end marker when stopping data signing.\n");
  printf("  -v\n");
  printf("     Verification mode checking the integrity of signed data.\n");
  printf("\n");
  printf("Example (sign):\n");
  printf(" TransferLog \"|./bin/%s -s password -e |./bin/qsrotate -o /var/log/apache/access_log\"\n", cmd);
  printf("\n");
  printf("Ecample (verify):\n");
  printf(" cat access_log | %s -s password -v\n", cmd);
  printf("\n");
  printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
  exit(1);
}

int main(int argc, const char * const argv[]) {
  apr_pool_t *pool;
  int verify = 0;
  char *cmd = strrchr(argv[0], '/');
  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-s") == 0) {
      if (--argc >= 1) {
	m_sec = *(++argv);
      }
    } else if(strcmp(*argv,"-S") == 0) {
      if (--argc >= 1) {
	m_sec = qs_readpwd(pool, *(++argv));
      } 
    } else if(strcmp(*argv,"-v") == 0) {
      verify = 1;
    } else if(strcmp(*argv,"-e") == 0) {
      m_logend = 1;
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd);
    }
    argc--;
    argv++;
  }

  if(m_sec == NULL) {
    usage(cmd);
  }
  if(verify) {
    long err = qs_verify(m_sec);
    if(err != 0) {
      return 1;
    }
  } else {
    if(m_logend) {
      signal(SIGTERM, qs_signal_exit);
    }
    qs_sign(m_sec);
    if(m_logend && (m_end != NULL)) {
      m_end(m_sec);
    }
  }

  apr_pool_destroy(pool);
  return 0;
}
