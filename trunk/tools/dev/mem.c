/**
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

static const char revision[] = "$Id: mem.c,v 1.2 2010-03-03 20:10:55 pbuchbinder Exp $";

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
  printf("usage: mem <pid>\n");
  printf("\n");
  printf("Calculates the heap used by the specified process\n");
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
	      printf("%s [%lu]\n", line, e-s);
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

static unsigned long readMaps(const char *pid) {
  apr_status_t rc;
  unsigned long shared = 0;
  unsigned long private = 0;
  apr_file_t *m;
  char *fname;
  apr_pool_t *pool;
  apr_pool_create(&pool, NULL);
  fname = apr_pstrcat(pool, "/proc/", pid, "/maps");
  if((rc = apr_file_open(&m, fname, APR_READ, APR_OS_DEFAULT, pool)) == APR_SUCCESS) {
    char line[4096];
    while(!fgetline(line, sizeof(line), m)) {
      count(pool, line, &shared, &private);
    }
    printf("private=%lu\n", private);
    printf("shared=%lu\n", shared);
    apr_file_close(m); 
  } else {
    fprintf(stderr, "ERROR: pid '%s' not available/readable (%d)\n", pid, rc);
    shared = 0;
    private = -1;
  }
  apr_pool_destroy(pool);
  return shared + private;
}

static void test() {
  int status;
  pid_t pid;
  char buf[1024];
  sprintf(buf, "%d", getpid());
  
  switch (pid = fork()) {
  case -1:
    exit(1);
  case 0:
    readMaps(buf);
    exit(0);
  default:
    waitpid(pid, &status, 0);
  }
  
  malloc(1024*1024);
  switch (pid = fork()) {
  case -1:
    exit(1);
  case 0:
    readMaps(buf);
    exit(0);
  default:
    waitpid(pid, &status, 0);
  }  
}


int main(int argc, const char * const argv[]) {
  argc--;
  argv++;
  if(argc < 1) {
    usage();
  }
  if(argc == 2) {
    if(strcmp(argv[1], "-v") == 0) {
      m_v = 1;
    }
  }
  apr_app_initialize(&argc, &argv, NULL);
  if(strcmp(argv[0], "test") == 0) {
    test();
  } else {
    readMaps(argv[0]);
  }
  return 0;
}
