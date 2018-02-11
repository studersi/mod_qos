/**
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2018 Pascal Buchbinder
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

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_lib.h>

#define CR 13
#define LF 10

static int m_v = 0;

static void usage() {
  printf("usage: mem [-v] <pid>\n");
  printf("\n");
  printf("Calculates the memory heap in bytes used by the specified process\n");
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  exit(1);
}

/**
 * reads a single line from f into the buffer s
 */
static int fgetline(char *s, int n, apr_file_t *f) {
  register int i = 0;
  s[0] = '\0';
  while (1) {
    if(apr_file_getc(&s[i], f) != APR_SUCCESS) {
      s[i] = EOF;
    }
    if (s[i] == CR) {
      if(apr_file_getc(&s[i], f) != APR_SUCCESS) {
        s[i] = EOF;
      }
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
      s[i] = '\0';
      return (apr_file_eof(f) == APR_EOF ? 1 : 0);
    }
    ++i;
  }
}

static int hex2c(int ch) {
  int i;
  if (apr_isdigit(ch)) {
    i = ch - '0';
  } else if (apr_isupper(ch)) {
    i = ch - ('A' - 10);
  } else {
    i = ch - ('a' - 10);
  }
  return i;
}

static unsigned long str2hex(const char *string) {
  unsigned long num = 0;
  unsigned long p = 1;
  int len = strlen(string) - 1;
  while(len >= 0) {
    int hex = hex2c(string[len]);
    num = num + (p * hex);
    p = p * 16;
    len--;
  }
  return num;
}

static char *getword(apr_pool_t *atrans, const char **line, char stop) {
  const char *pos = *line;
  int len;
  char *res;
  
  while ((*pos != stop) && *pos) {
    ++pos;
  }
  len = pos - *line;
  res = (char *)apr_palloc(atrans, len + 1);
  memcpy(res, *line, len);
  res[len] = 0;
  
  if (stop) {
    while (*pos == stop) {
      ++pos;
    }
  }
  *line = pos;
  return res;
}

static void count(apr_pool_t *pool, const char *line,
		  unsigned long *shared, unsigned long *private) {
  const char *r = line;
  char *start = getword(pool, &r, '-');
  if(start) {
    char *end = getword(pool, &r, ' ');
    if(end) {
      char *perms = getword(pool, &r, ' ');
      if(perms) {
	char *off = getword(pool, &r, ' ');
	if(off) {
	  char *dev = getword(pool, &r, ' ');
	  if(dev) {
	    unsigned long s = str2hex(start);
	    unsigned long e = str2hex(end);
	    if(m_v) {
	      printf("%s [%lukb]\n", line, (e-s)/1024);
	    }
	    if(strcmp(dev, "00:00") == 0) {
	      if(strcmp(perms, "rw-p") == 0) {
		*private = *private + (e-s);
	      } else if(strcmp(perms, "rw-s") == 0) {
		*shared = *shared + (e-s);
	      }
	    }
	  }
	}
      }
    }
  }  
  return;
}

static void readSMaps(const char *pid) {
  apr_status_t rc;
  apr_file_t *m;
  char *fname;
  apr_pool_t *pool;
  apr_pool_create(&pool, NULL);
  fname = apr_pstrcat(pool, "/proc/", pid, "/smaps", NULL);
  if((rc = apr_file_open(&m, fname, APR_READ, APR_OS_DEFAULT, pool)) == APR_SUCCESS) {
    char line[4096];
    while(!fgetline(line, sizeof(line), m)) {
      if(1) {
	if(strncmp(line, "Size:", strlen("Size:")) == 0) {
	  printf("%s\n", line);
	}
	if(strstr(line, " 00:00 ")) {
	  printf("%s\n", line);
	}
      } else {
	printf("%s\n", line);
      }
    }
    apr_file_close(m); 
  } else {
    char buf[1024];
    apr_strerror(rc, buf, sizeof(buf));
    fprintf(stderr, "ERROR: pid's (%s) maps file not available/readable (%s)\n", pid, buf);
  }
  apr_pool_destroy(pool);
}

static unsigned long readMaps(const char *pid) {
  apr_status_t rc;
  unsigned long shared = 0;
  unsigned long private = 0;
  apr_file_t *m;
  char *fname;
  apr_pool_t *pool;
  apr_pool_create(&pool, NULL);
  fname = apr_pstrcat(pool, "/proc/", pid, "/maps", NULL);
  if((rc = apr_file_open(&m, fname, APR_READ, APR_OS_DEFAULT, pool)) == APR_SUCCESS) {
    char line[4096];
    while(!fgetline(line, sizeof(line), m)) {
      count(pool, line, &shared, &private);
    }
    printf("private=%lu\n", private);
    printf("shared=%lu\n", shared);
    apr_file_close(m); 
  } else {
    char buf[1024];
    apr_strerror(rc, buf, sizeof(buf));
    fprintf(stderr, "ERROR: pid's (%s) maps file not available/readable (%s)\n", pid, buf);
    shared = 0;
    private = -1;
  }
  apr_pool_destroy(pool);
  return shared + private;
}

static void testFunc() {
  int m = 1024 * 1024;
  char ppid[1024];
  char *v;
  sprintf(ppid, "%d", getpid());
  printf(">initial (%s)\n", ppid);
  readMaps(ppid);

  printf(">calloc %d bytes\n", m);
  v = calloc(m, 1);
  readMaps(ppid);
  readSMaps(ppid);

  printf(">free\n");
  free(v);
  readMaps(ppid);
}


int main(int argc, const char * const argv[]) {
  const char *pid;
  int test = 0;
  apr_app_initialize(&argc, &argv, NULL);
  argc--;
  argv++;
  if(argc < 1) {
    usage();
  }
  if(argc == 2) {
  }
  while(argc >= 1) {
    if(strcmp(argv[0], "-v") == 0) {
      m_v = 1;
    } else if(strcmp(argv[0], "test") == 0) {
      test = 1;
    } else {
      pid = argv[0];
    }
    argc--;
    argv++;
  }
  if(test) {
    testFunc();
  } else {
    readMaps(pid);
  }
  return 0;
}
