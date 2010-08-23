/**
 * Utilities for the quality of service module mod_qos.
 *
 * Log data signing tool to ensure data integrity.
 *
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2010 Pascal Buchbinder
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

static const char revision[] = "$Id: qssign.c,v 1.2 2010-08-19 19:44:35 pbuchbinder Exp $";

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <config.h>

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

#define MAX_LINE 65536
#define CR 13
#define LF 10
#define SEQDIG "12"
#define MAX_STRING_LEN 32768

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

static void qs_sign(const char *sec) {
  int sec_len = strlen(sec);
  long nr = 1;
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  /* <data> ' ' <sequence number> '#' <hmac>*/
  int line_size = sizeof(line) - 1 - dig - 1 - (2*HMAC_MAX_MD_CBLOCK) - 1;
  while(qs_getLine(line, line_size)) {
    HMAC_CTX ctx;
    unsigned char data[HMAC_MAX_MD_CBLOCK];
    unsigned int len;
    char *m;
    int data_len;
    sprintf(&line[strlen(line)], " %."SEQDIG"ld", nr);
    HMAC_Init(&ctx, sec, sec_len, EVP_sha1());
    HMAC_Update(&ctx, (const unsigned char *)line, strlen(line));
    HMAC_Final(&ctx, data, &len);
    m = calloc(1, apr_base64_encode_len(len) + 1);
    data_len = apr_base64_encode(m, (char *)data, len);
    m[data_len] = '\0';
    printf("%s#%s\n", line, m);
    free(m);
    nr++;
  }
  return;
}

static long qs_verify(const char *sec) {
  int sec_len = strlen(sec);
  long err = 0; // errors
  long lnr = 0; // line number
  long nr = -1; // sequence number
  char line[MAX_LINE];
  int line_size = sizeof(line);
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
	if(nr != -1) {
	  if(nr != ns) {
	    err++;
	    fprintf(stderr, "ERROR on line %ld: wrong sequence (expect %."SEQDIG"ld)\n", lnr, nr);
	  }
	}
	if(valid) {
	  nr = ns;
	}
      }
    } else {
      err++;
      fprintf(stderr, "ERROR on line %ld: missing signature/sequence\n", lnr);
    }
    if(valid) {
      nr++;
    }
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
  printf("Usage: %s -s|S <secret> [-v]\n", cmd);
  printf("\n");
  printf("Summary\n");
  printf("%s is a log data integrity check tool. It reads log data\n", cmd);
  printf("from stdin (pipe) and writes the signed data to stdout.\n");
  printf("\n");
  printf("Options\n");
  printf("  -s <secret>\n");
  printf("     Passphrase used for calculate signature.\n");
  printf("  -S <program>\n");
  printf("     Specifies a program which writes the passphrase to stdout.\n");
  printf("  -v\n");
  printf("     Verification mode checking the integrity of signed data.\n");
  printf("\n");
  printf("Example (sign):\n");
  printf(" TransferLog \"|./bin/%s -s password |qsrotate -o /var/log/apache/access_log\"\n", cmd);
  printf("\n");
  printf("Ecample (verify):\n");
  printf(" cat access_log | %s -s password -v\n", cmd);
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  exit(1);
}

int main(int argc, const char * const argv[]) {
  apr_pool_t *pool;
  int verify = 0;
  const char *sec = NULL;
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
	sec = *(++argv);
      }
    } else if(strcmp(*argv,"-S") == 0) {
      if (--argc >= 1) {
	sec = qs_readpwd(pool, *(++argv));
      } 
    } else if(strcmp(*argv,"-v") == 0) {
      verify = 1;
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd);
    }
    argc--;
    argv++;
  }

  if(sec == NULL) {
    usage(cmd);
  }
  if(verify) {
    long err = qs_verify(sec);
    if(err != 0) {
      return 1;
    }
  } else {
    qs_sign(sec);
  }

  apr_pool_destroy(pool);
  return 0;
}
