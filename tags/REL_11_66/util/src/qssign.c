/**
 * Utilities for the quality of service module mod_qos.
 *
 * qssign.c: Log data signing tool to ensure data integrity.
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2020 Pascal Buchbinder
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
 */

static const char revision[] = "$Id$";

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <signal.h>

/* openssl */
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* PCRE */
#include <pcre.h>

/* apr/apr-util */
#define QS_USEAPR 1
#include <apr.h>
#include <apr_base64.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>
#include <apr_file_io.h>
#include <apr_time.h>

#include "qs_util.h"
#include "qs_apo.h"

#define SEQDIG "12"
#define QS_END   "qssign---end-of-data"
#define QS_START "qssign---------start"

static const char *m_start_fmt = "";
static const char *m_end_fmt = "";
static long m_nr = 1;
static int  m_logend = 0;
static void (*m_end)(const char *, int) = NULL;
static int m_end_pos = 0;
static const char *m_sec = NULL;
static const EVP_MD *m_evp;
static const pcre *m_filter = NULL;

typedef struct {
  const char* start_fmt;
  const char* end_fmt;
  const char* pattern;
  const char* test;
} qos_p_t;

#define severity "[A-Z]+"

static const qos_p_t pattern[] = {
  {
    "%s | INFO  | "QS_START,
    "%s | INFO  | "QS_END,
    "^[0-9]{4}[-][0-9]{2}[-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}[ ]+[|][ ]+"severity"[ ]+[|][ ]+[a-zA-Z0-9]+",
    "2010-04-14 20:18:37,464 | INFO  | org.hibernate.cfg.Configuration"
  },
  {
    "%s INFO  "QS_START,
    "%s INFO  "QS_END,
    "^[0-9]{4}[-][0-9]{2}[-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}[ ]+"severity"[ ]+",
    "2011-08-30 07:27:22,738 INFO  loginId='test'"
  },
  {
    "%s qssign          start                                    INFO  "QS_START,
    "%s qssign          end                                      INFO  "QS_END,
    "^[0-9]{4}[-][0-9]{2}[-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}[ ]+[a-zA-Z0-9\\.-]+[ ]+[a-zA-Z0-9\\.-]+[ ]+"severity"[ ]+",
    "2011-09-01 07:37:17,275 main            org.apache.catalina.startup.Catalina     INFO  Server"
  },
  {
    "%s INFO  "QS_START,
    "%s INFO  "QS_END,
    "^[0-9]{4}[-][0-9]{2}[-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}[ ]+",
    "2011-08-30 07:27:22,738 "
  },
  { NULL, NULL, NULL }
};

/**
 * Writes the signed log line to stdout.
 *
 * @param line Data to sign
 * @param line_size Length of the data
 * @param sec Secret
 * @param sec_len Length of the secret
 */
static void qs_write(char *line, int line_size, const char *sec, int sec_len) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX hmac;
  HMAC_CTX *hmac_p = &hmac;
#else
  HMAC_CTX *hmac_p;
#endif
  unsigned char data[HMAC_MAX_MD_CBLOCK];
  unsigned int len;
  char *m;
  int data_len;
  sprintf(&line[strlen(line)], " %."SEQDIG"ld", m_nr);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX_init(hmac_p);
#else
  hmac_p = HMAC_CTX_new();
#endif
  HMAC_Init_ex(hmac_p, sec, sec_len, m_evp, NULL);
  HMAC_Update(hmac_p, (const unsigned char *)line, strlen(line));
  HMAC_Final(hmac_p, data, &len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX_cleanup(hmac_p);
#else
  HMAC_CTX_free(hmac_p);
#endif
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
static void qs_end_apache_err(const char *sec, int start) {
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  char time_string[1024];
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  strftime(time_string, sizeof(time_string), "%a %b %d %H:%M:%S %Y", ptr);
  if(start) {
    sprintf(line, "[%s] [notice] "QS_START, time_string);
  } else {
    sprintf(line, "[%s] [notice] "QS_END, time_string);
  }
  qs_write(line, line_size, sec, sec_len);
  return;
}

/*
 * 12.12.12.12 - - [03/Dec/2010:07:36:51 +0100] ...............
 */
static void qs_end_apache_acc(const char *sec, int start) {
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
  if(start) {
    sprintf(line, "0.0.0.0 - - [%s %c%.2d%.2d] "QS_START, time_string, sign, timz / (60*60), (timz % (60*60)) / 60);
  } else {
    sprintf(line, "0.0.0.0 - - [%s %c%.2d%.2d] "QS_END, time_string, sign, timz / (60*60), (timz % (60*60)) / 60);
  }
  qs_write(line, line_size, sec, sec_len);
  return;
}

/*
 * 2010 12 03 17:00:30.425 qssign     end        0.0              5-NOTICE:  ..............
 */
static void qs_end_nj(const char *sec, int start) {
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
  if(start) {
    sprintf(line, "%s qssign     start      0.0%s 5-NOTICE:  "QS_START, time_string, buf);
  } else {
    sprintf(line, "%s qssign     end        0.0%s 5-NOTICE:  "QS_END, time_string, buf);
  }
  qs_write(line, line_size, sec, sec_len);
  return;
}

/*
 * 2010-04-14 20:18:37,464 ... (using m_fmt)
 */
static void qs_end_lj(const char *sec, int start) {
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  char time_string[1024];
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S,000", ptr);
  if(start) {
    sprintf(line, m_start_fmt, time_string);
  } else {
    sprintf(line, m_end_fmt, time_string);
  }
  qs_write(line, line_size, sec, sec_len);
  return;
}

/*
 * Dec  6 04:00:06 localhost kernel:
 */
static void qs_end_lx(const char *sec, int start) {
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
  if(start) {
    sprintf(line, "%s %s qssign: "QS_START, time_string, hostname);
  } else {
    sprintf(line, "%s %s qssign: "QS_END, time_string, hostname);
  }
  qs_write(line, line_size, sec, sec_len);
  return;
}

/*
 * 2013/11/13 17:38:41 [error] 6577#0: *1 open()
 */
static void qs_end_ngx(const char *sec, int start) {
  int sec_len = strlen(sec);
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  char time_string[1024];
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  strftime(time_string, sizeof(time_string), "%Y/%m/%d %H:%M:%S", ptr);
  if(start) {
    sprintf(line, "%s [notice] 0#0: "QS_END, time_string);
  } else {
    sprintf(line, "%s [notice] 0#0: "QS_END, time_string);
  }
  qs_write(line, line_size, sec, sec_len);
  return;
}

void qs_signal_exit(int e) {
  if(m_logend && (m_end != NULL)) {
    m_end(m_sec, 0);
  }
  exit(0);
}

/**
 * Tries to find out a suitable log line format which is used
 * to log sign end messages (so let the verifier known, that the
 * data ends nothing has been cut off).
 *
 * Sets the format to global variables.
 *
 * known pattern
 * - [Fri Dec 03 07:37:40 2010] [notice] .........
 * - 12.12.12.12 - - [03/Dec/2010:07:36:51 +0100] ...............
 * - 2010 12 03 17:00:30.425 qssign     end        0.0              5-NOTICE:  ..............
 *                                                 46  <- var ->    63      71
 * - Dec  6 04:00:06 localhost kernel:
 * - some 2010-12-03 17:00:30,425 ...
 *
 * @param s
 */
static void qs_set_format(char *s) {
  regex_t r_apache_err; 
  regex_t r_apache_acc;
  regex_t r_nj;
  regex_t r_lx;
  regex_t r_ngx;
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
  if(regcomp(&r_ngx,
	     "^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \\[[a-z]+\\] [0-9]+#[0-9]+: ",
	     REG_EXTENDED) != 0) {
    fprintf(stderr, "failed to compile regex (ngx)\n");
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
  } else if(regexec(&r_ngx, s, 0, NULL, 0) == 0) {
    m_end = &qs_end_ngx;    
  }
  // search within the generic yyyy-mm-dd hh-mm-ss,mmm patterns
  if(!m_end) {
    const qos_p_t *p = pattern;
    while(p->end_fmt) {
      regex_t r_j;
      if(regcomp(&r_j, p->pattern, REG_EXTENDED) != 0) {
	fprintf(stderr, "failed to compile regex (%s)\n", p->pattern);
	exit(1);
      }
      if(regexec(&r_j, s, 0, NULL, 0) == 0) {
	m_start_fmt = p->start_fmt;
	m_end_fmt = p->end_fmt;
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

/**
 * Process the data from stdin.
 *
 * @param sec Passphrase
 */
static void qs_sign(const char *sec) {
  int sec_len = strlen(sec);
  char *line = calloc(1, MAX_LINE_BUFFER+1);
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = MAX_LINE_BUFFER - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  int line_len;
  while(fgets(line, MAX_LINE_BUFFER, stdin) != NULL) {
    line_len = strlen(line) - 1;
    while(line_len > 0) { // cut tailing CR/LF
      if(line[line_len] >= ' ') {
	break;
      }
      line[line_len] = '\0';
      line_len--;
    }
    if(m_logend && (m_end == NULL)) {
      qs_set_format(line);
      m_end(m_sec, 1);
    }
    if(pcre_exec(m_filter, NULL, line, line_size, 0, 0, NULL, 0) >= 0) {
      printf("%s\n", line);
      fflush(stdout);
    } else {
      qs_write(line, line_size, sec, sec_len);
    }
  }
  return;
}

static int isSpecialLine(const char *line, const char *marker) {
  char *se_marker = strstr(line, marker);
  if(se_marker != NULL) {
    /* QS_END/START + " " + SEQDIG */
    int sz = strlen(marker) + 1 + atoi(SEQDIG);
    if(sz == (strlen(line) - (se_marker - line))) {
      return 1;
    }
  }
  return 0;
}

static long qs_verify(const char *sec) {
  int end_seen = 0;
  int sec_len = strlen(sec);
  long err = 0; // errors
  long lineNumber = 0; // line number of the file / input data
  char *line = calloc(1, MAX_LINE_BUFFER+1);
  int line_size = MAX_LINE_BUFFER;
  int line_len;
  m_nr = -1;        // expected sequence number (start with any)
  long nr_alt = -1; // alternatively expected sequence number (if a line was injected)
  long nr_alt_lineNumber = -1;
  long nr_usr1_lineNumber = -1; // we may have lines written by a prev. qssign binary (while graceful restart)
  while(fgets(line, line_size, stdin) != NULL) {
    int valid = 0;
    long msgSeqNr = 0;
    int isOldProcess = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX hmac;
    HMAC_CTX *hmac_p = &hmac;
#else
    HMAC_CTX *hmac_p;
#endif
    unsigned char data[HMAC_MAX_MD_CBLOCK];
    unsigned int len;
    char *m;
    int data_len;
    char *sig;
    char *seq;
    line_len = strlen(line) - 1;
    while(line_len > 0) { // cut tailing CR/LF
      if(line[line_len] >= ' ') {
	break;
      }
      line[line_len] = '\0';
      line_len--;
    }
    sig = strrchr(line, '#');
    seq = strrchr(line, ' ');
    lineNumber++;
    if(seq && sig) {
      sig[0] = '\0';
      sig++;
      /* verify hmac */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      HMAC_CTX_init(hmac_p);
#else
      hmac_p = HMAC_CTX_new();
#endif
      HMAC_Init_ex(hmac_p, sec, sec_len, m_evp, NULL);
      HMAC_Update(hmac_p, (const unsigned char *)line, strlen(line));
      HMAC_Final(hmac_p, data, &len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      HMAC_CTX_cleanup(hmac_p);
#else
      HMAC_CTX_free(hmac_p);
#endif
      m = calloc(1, apr_base64_encode_len(len) + 1);
      data_len = apr_base64_encode(m, (char *)data, len);
      m[data_len] = '\0';
      if(strcmp(m, sig) != 0) {
	err++;
	fprintf(stderr, "ERROR on line %ld: invalid signature\n", lineNumber);
	/* message may be modified/corrupt or inserted: next line may have
	   the next sequence number (modified) or the same (inserted) */
	nr_alt = m_nr + 1;
	nr_alt_lineNumber = lineNumber + 1;
      } else {
	valid = 1;
      }
      free(m);
      /* verify sequence */
      seq++;
      msgSeqNr = atol(seq);
      if(msgSeqNr == 0) {
	err++;
	fprintf(stderr, "ERROR on line %ld: invalid sequence\n", lineNumber);
      } else {
	if(m_nr != -1) {
	  if(lineNumber == nr_alt_lineNumber) {
	    // last line was modified
	    if(m_nr != msgSeqNr) {
	      // and therefore, we also accept the next sequence number
	      m_nr = nr_alt;
	    }
	    nr_alt = -1;
	    nr_alt_lineNumber = -1;
	  }
	  if(valid && isSpecialLine(line, QS_START)) {
	    // new start line (graceful restart)
	    // we expect now msg nummber 1
	    // but still acept the old until we get the end marker
	    nr_usr1_lineNumber = m_nr;
	    m_nr = 1; 
	  }
	  if(valid && nr_usr1_lineNumber == msgSeqNr) {
	    // msg from old process is okay...
	    nr_usr1_lineNumber++;
	    isOldProcess = 1;
	  } else {
	    if(m_nr != msgSeqNr) {
	      if(msgSeqNr == 1) {
		if(!end_seen) {
		  err++;
		  fprintf(stderr, "ERROR on line %ld: wrong sequence, server restart? (expect %."SEQDIG"ld)\n",
			  lineNumber, m_nr);
		}
	      } else {
		err++;
		fprintf(stderr, "ERROR on line %ld: wrong sequence (expect %."SEQDIG"ld)\n", lineNumber, m_nr);
	      }
	    } else {
	      // well done - this is the sequence number we expet
	    }
	  }
	} else if(m_logend) {
	  // log should (if not rotated) start with message 1
	  if(msgSeqNr != 1) {
	    fprintf(stderr, "NOTICE: log starts with sequence %."SEQDIG"ld, log rotation?"
		    " (expect %."SEQDIG"d)\n", msgSeqNr, 1);
	  }
	}
	if(valid && !isOldProcess) {
	  // adjust
	  m_nr = msgSeqNr;
	}
      }
    } else {
      err++;
      fprintf(stderr, "ERROR on line %ld: missing signature/sequence\n", lineNumber);
    }
    end_seen = 0;
    if(valid) {
      if(!isOldProcess) {
	m_nr++;
      }
      if(isSpecialLine(line, QS_END)) {
	if(nr_usr1_lineNumber == -1) {
	  end_seen = 1;
	} else {
	  nr_usr1_lineNumber = -1; // no more messages from an old process
	}
      }
    }
  }
  if(m_logend && !end_seen) {
    fprintf(stderr, "NOTICE: no end marker seen, log rotation? (expect %."SEQDIG"ld)\n", m_nr);
  }
  return err;
}

static void usage(char *cmd, int man) {
  if(man) {
    //.TH [name of program] [section number] [center footer] [left footer] [center header]
    printf(".TH %s 1 \"%s\" \"mod_qos utilities %s\" \"%s man page\"\n", qs_CMD(cmd), man_date,
	   man_version, cmd);
  }
  printf("\n");
  if(man) {
    printf(".SH NAME\n");
  }
  qs_man_print(man, "%s - an utility to sign and verify the integrity of log data.\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -s|S <secret> [-e] [-v] [-u <name>] [-f <regex>] [-a 'sha1'|'sha256']\n", man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "%s is a log data integrity check tool. It reads log data\n", cmd);
  qs_man_print(man, "from stdin (pipe) and writes the data to stdout adding a sequence\n");
  qs_man_print(man, "number and signature to ever log line.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -s <secret>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Passphrase used to calculate signature.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -S <program>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifies a program which writes the passphrase to stdout.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -e\n");
  if(man) printf("\n");
  qs_man_print(man, "     Writes start/end marker when starting/stopping data signing.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -v\n");
  if(man) printf("\n");
  qs_man_print(man, "     Verification mode checking the integrity of signed data.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -u <name>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Becomes another user, e.g. www-data.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -f <regex>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Filter pattern (case sensitive regular expression) for messages\n");
  qs_man_print(man, "     which do not need to be signed.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -a 'sha1'|'sha256'\n");
  if(man) printf("\n");
  qs_man_print(man, "     Specifes the algorithm to use. Default is sha1.\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
    printf("Sign:\n");
    printf("\n");
  } else {
    printf("Example (sign):\n");
  }
  qs_man_println(man, " TransferLog \"|/usr/bin/%s -s password -e |/usr/bin/qsrotate -o /var/log/apache/access.log\"\n", cmd);
  printf("\n");
  if(man) {
    printf("\n");
    printf("Verify:\n");
    printf("\n");
  } else {
    qs_man_print(man, "Example (verify):\n");
  }
  qs_man_println(man, " cat access.log | %s -s password -v\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qshead(1), qslog(1), qslogger(1), qspng(1), qsre(1), qsrespeed(1), qsrotate(1), qstail(1)\n");
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

int main(int argc, const char * const argv[]) {
  apr_pool_t *pool;
  int verify = 0;
  char *cmd = strrchr(argv[0], '/');
  const char *username = NULL;
  const char *filter = NULL;
  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  m_evp = EVP_sha1();
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
    } else if(strcmp(*argv,"-u") == 0) { /* switch user id */
      if (--argc >= 1) {
        username = *(++argv);
      }
    } else if(strcmp(*argv,"-f") == 0) { /* filter */
      if (--argc >= 1) {
        filter = *(++argv);
      }
    } else if(strcmp(*argv,"-a") == 0) { /* set alg */
      if (--argc >= 1) {
        const char *alg = *(++argv);
	if(strcasecmp(alg, "SHA256") == 0) {
	  m_evp = EVP_sha256();
	} else if(strcasecmp(alg, "SHA1") != 0) {
	  m_evp = NULL;
	}
      } else {
	m_evp = NULL;
      }
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    }
    argc--;
    argv++;
  }

  if(filter != NULL) {
    const char *errptr = NULL;
    int erroffset;
    m_filter = pcre_compile(filter, 0, &errptr, &erroffset, NULL);
    if(m_filter == NULL) {
      fprintf(stderr, "failed to compile filter pattern <%s> at position %d,"
            " reason: %s\n", filter, erroffset, errptr);
      exit(1);
    }
  }

  if(m_evp == NULL) {
    usage(cmd, 0);
  }
    
  if(m_sec == NULL) {
    usage(cmd, 0);
  }

  qs_setuid(username, cmd);

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
      m_end(m_sec, 0);
    }
  }

  apr_pool_destroy(pool);
  return 0;
}
