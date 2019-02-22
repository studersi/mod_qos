/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2019 Pascal Buchbinder
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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>

/* apr/apr-util */
#include <apr.h>
#include <apr_base64.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>
#include <apr_file_io.h>
#include <apr_time.h>

#include "qs_util.h"
#include "qs_apo.h"

static apr_table_t *qs_args(apr_pool_t *pool, const char *line) {
  char *last = apr_pstrdup(pool, line);
  apr_table_t* table = apr_table_make(pool, 10);
  char *val;
  while((val = apr_strtok(NULL, " ", &last))) {
    apr_table_addn(table, val, "");
  }
  return table;
}

static void qs_failedexec(const char *msg, const char *cmd, apr_status_t status) {
  char buf[MAX_LINE];
  apr_strerror(status, buf, sizeof(buf));
  fprintf(stderr, "ERROR %s '%s': '%s'\n", msg, cmd, buf);
  exit(1);
}

/**
 * Reads a passphrase using the defined passphrase getter (executes
 * the program and reads the passphras from stdout).
 * 
 * @param pool To allocate memory
 * @param prg Path of the program to exectue
 * @return The passphrase
 */
char *qs_readpwd(apr_pool_t *pool, const char *prg) {
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
  apr_size_t len = MAX_LINE;
  char *buf = apr_pcalloc(pool, len);

  args = apr_pcalloc(pool, (apr_table_elts(a)->nelts + 1) * sizeof(const char *));
  entry = (apr_table_entry_t *) apr_table_elts(a)->elts;
  for(i = 0; i < apr_table_elts(a)->nelts; i++) {
    args[i] = entry[i].key;
  }
  args[i] = NULL;

  if(cmd == NULL) {
    qs_failedexec("can't read password, invalid executable", prg, APR_EGENERAL);
  }
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
