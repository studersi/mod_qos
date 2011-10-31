/**
 * Command line execution utility for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further details.
 *
 * Copyright (C) 2011 Pascal Buchbinder
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is released under the GPL with the additional
 * exemption that compiling, linking, and/or using OpenSSL is allowed.
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

static const char revision[] = "$Id: qsexec.c,v 1.5 2011-10-31 20:57:09 pbuchbinder Exp $";

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <pwd.h>

/* apr */
#include <pcre.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>

#include "qs_util.h"

#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif
#define MAX_REG_MATCH 10

typedef struct {
    int rm_so;
    int rm_eo;
} regmatch_t;

static void usage(char *cmd, int man) {
  if(man) {
    //.TH [name of program] [section number] [center footer] [left footer] [center header]
    printf(".TH %s 1 \"%s\" \"mod_qos utilities %s\" \"%s man page\n", qs_CMD(cmd), man_date, man_version, cmd);
  }
  printf("\n");
  if(man) {
    printf(".SH NAME\n");
  }
  printf("%s - parses the data received via stdin and executes the defined command.\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -e <pattern> [-t <number>:<sec>] [-c <pattern> [<command string>]]\n", man ? "" : "Usage: ", cmd);
  qs_man_print(man, "       [-p] [-u <user>] <command string>\n");
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  printf("%s reads log lines from stdin and searches for the defined pattern.\n", cmd);
  printf("It executes the defined command string on pattern match.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  printf("  -e <pattern>\n");
  printf("     Specifes the search pattern causing an event which shall trigger the\n");
  printf("     command.\n");
  printf("  -t <number>:<sec>\n");
  printf("     Defines the number of pattern match within the the defined number of\n");
  printf("     seconds in order to trigger the command execution. By default, every\n");
  printf("     pattern match causes command execution.\n");
  printf("  -c <pattern> [<command string>]\n");
  printf("     Pattern which clears the event counter. Executes optionally a command\n");
  printf("     if an event command has been executed before.\n");
  printf("  -p\n");
  printf("     Writes data also to stdout (for piped logging).\n");
  printf("  -u <name>\n");
  printf("     Become another user, e.g. www-data.\n");
  printf("  <command string>\n");
  printf("     Defines the event command string where $0-$9 are substituted by the\n");
  printf("     submatches of the regular expression.\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
  }
  printf("Executes the deny.sh script providing the IP addresses of\n");
  printf("the client causing a mod_qos(031) messages whenever the log message\n");
  printf("appears 10 times within at most one minute:\n");
  qs_man_println(man, "  ErrorLog \"|%s -e 'mod_qos\\(031\\).*, c=([0-9.]*)' -t 10:60 '/bin/deny.sh $1'\"\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsfilter2(1), qsgrep(1), qslog(1), qspng(1), qsrotate(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://opensource.adnovum.ch/mod_qos/\n");
  } else {
    printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
  }
  exit(1);
}

char *qs_pregsub(apr_pool_t *pool, const char *input,
		 const char *source, size_t nmatch,
		 regmatch_t pmatch[]) {
  const char *src = input;
  char *dest, *dst;
  char c;
  size_t no;
  int len;
  if(!source) {
    return NULL;
  }
  if(!nmatch) {
    return apr_pstrdup(pool, src);
  }
  /* First pass, find the size */  
  len = 0;
  while((c = *src++) != '\0') {
    if(c == '&')
      no = 0;
    else if (c == '$' && apr_isdigit(*src))
      no = *src++ - '0';
    else
      no = 10;
    
    if (no > 9) {                /* Ordinary character. */
      if (c == '\\' && (*src == '$' || *src == '&'))
	src++;
      len++;
    }
    else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
      len += pmatch[no].rm_eo - pmatch[no].rm_so;
    }
    
  }
  dest = dst = apr_pcalloc(pool, len + 1);
  /* Now actually fill in the string */
  src = input;
  while ((c = *src++) != '\0') {
    if (c == '&')
      no = 0;
    else if (c == '$' && apr_isdigit(*src))
      no = *src++ - '0';
    else
      no = 10;

    if (no > 9) {                /* Ordinary character. */
      if (c == '\\' && (*src == '$' || *src == '&'))
	c = *src++;
      *dst++ = c;
    }
    else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
      len = pmatch[no].rm_eo - pmatch[no].rm_so;
      memcpy(dst, source + pmatch[no].rm_so, len);
      dst += len;
    }
  }
  *dst = '\0';
  return dest;
}

int qs_regexec(pcre *preg, const char *string,
	       apr_size_t nmatch, regmatch_t pmatch[]) {
  int rc;
  int options = 0;
  int *ovector = NULL;
  int small_ovector[POSIX_MALLOC_THRESHOLD * 3];
  int allocated_ovector = 0;
  if (nmatch > 0) {
    if (nmatch <= POSIX_MALLOC_THRESHOLD) {
      ovector = &(small_ovector[0]);
    } else {
      ovector = (int *)malloc(sizeof(int) * nmatch * 3);
      if (ovector == NULL) {
	return 1;
      }
      allocated_ovector = 1;
    }
  }
  rc = pcre_exec(preg, NULL, string, (int)strlen(string), 0, options, ovector, nmatch * 3);
  if (rc == 0) rc = nmatch;    /* All captured slots were filled in */
  if (rc >= 0) {
    apr_size_t i;
    for (i = 0; i < (apr_size_t)rc; i++) {
      pmatch[i].rm_so = ovector[i*2];
      pmatch[i].rm_eo = ovector[i*2+1];
    }
    if (allocated_ovector) free(ovector);
    for (; i < nmatch; i++) pmatch[i].rm_so = pmatch[i].rm_eo = -1;
    return 0;
  } else {
    if (allocated_ovector) free(ovector);
    return rc;
  }
}

int main(int argc, const char * const argv[]) {
  const char *username = NULL;
  int nr = 0;
  char line[32768];
  apr_pool_t *pool;
  char *cmd = strrchr(argv[0], '/');
  const char *command = NULL;
  const char *pattern = NULL;
  const char *clearcommand = NULL;
  const char *clearpattern = NULL;
  int executed = 0;
  pcre *preg;
  pcre *clearpreg;
  int nsub;
  const char *errptr = NULL;
  int erroffset;
  regmatch_t regm[MAX_REG_MATCH];
  time_t sec = 0;
  int threshold = 0;
  int counter = 0;
  time_t countertime;
  static int pass = 0;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-e") == 0) {
      if (--argc >= 1) {
	pattern = *(++argv);
      }
    } else if(strcmp(*argv,"-u") == 0) {
      if (--argc >= 1) {
	username = *(++argv);
      }
    } else if(strcmp(*argv,"-c") == 0) {
      if (--argc >= 1) {
	clearpattern = *(++argv);
      }
      if (argc > 2 && *argv[0] != '-') {
	clearcommand = *(++argv);
	--argc;
      }
    } else if(strcmp(*argv,"-t") == 0) {
      if (--argc >= 1) {
	char *str = apr_pstrdup(pool, *(++argv));
	char *tme = strchr(str, ':');
	if(tme == NULL) {
	  fprintf(stderr,"[%s]: ERROR, invalid number:sec format\n", cmd);
	  exit(1);
	}
	tme[0] = '\0';
	tme++;
	threshold = atoi(str);
	sec = atol(tme);
	if(threshold == 0 || sec == 0) {
	  fprintf(stderr,"[%s]: ERROR, invalid number:sec format\n", cmd);
	  exit(1);
	}
      }
    } else if(strcmp(*argv,"-p") == 0) {
      pass = 1;
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    } else {
      command = *argv;
    }
    argc--;
    argv++;
  }

  if(pattern == NULL || command == NULL) {
    usage(cmd, 0);
  }

  if(username && getuid() == 0) {
    struct passwd *pwd = getpwnam(username);
    uid_t uid, gid;
    if(pwd == NULL) {
      fprintf(stderr,"[%s]: ERROR, unknown user id %s\n", cmd, username);
      exit(1);
    }
    uid = pwd->pw_uid;
    gid = pwd->pw_gid;
    setgid(gid);
    setuid(uid);
    if(getuid() != uid) {
      fprintf(stderr,"[%s]: ERROR, setuid failed (%s,%d)\n", cmd, username, uid);
      exit(1);
    }
    if(getgid() != gid) {
      fprintf(stderr,"[%s]: ERROR, setgid failed (%d)\n", cmd, gid);
      exit(1);
    }
  }

  preg = pcre_compile(pattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(!preg) {
    fprintf(stderr, "ERROR, could not compile '%s' at position %d, reason: %s\n",
	    pattern, erroffset, errptr);
    exit(1);
  }
  nsub = pcre_info((const pcre *)preg, NULL, NULL);
  if(clearpattern) {
    clearpreg = pcre_compile(clearpattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
    if(!clearpreg) {
      fprintf(stderr, "ERROR, could not compile '%s' at position %d, reason: %s\n",
	      clearpattern, erroffset, errptr);
      exit(1);
    }
  }

  while(fgets(line, sizeof(line), stdin) != NULL) {
    nr++;
    if(pass) {
      printf("%s", line);
    }
    if(clearpattern && (qs_regexec(clearpreg, line, MAX_REG_MATCH, regm) == 0)) {
      counter = 0;
      countertime = 0;
      if(clearcommand && executed) {
	char *replaced = qs_pregsub(pool, clearcommand, line, MAX_REG_MATCH, regm);
	if(!replaced) {
	  fprintf(stderr, "[%s]: ERROR, failed to substitute submatches '%s' in (%s)\n", cmd, clearcommand, line);
	} else {
	  system(replaced);
	}
	executed = 0;
      }
    } else if(qs_regexec(preg, line, MAX_REG_MATCH, regm) == 0) {
      char *replaced = qs_pregsub(pool, command, line, MAX_REG_MATCH, regm);
      if(!replaced) {
	fprintf(stderr, "[%s]: ERROR, failed to substitute submatches '%s' in (%s)\n", cmd, command, line);
      } else {
	counter++;
	if(counter == 1) {
	  countertime = time(NULL);
	}
	if(counter >= threshold) {
	  if(countertime + sec >= time(NULL)) {
	    system(replaced);
	    executed = 1;
	  }
	  countertime = 0;
	  counter = 0;
	}
      }
      apr_pool_clear(pool);
    }
  }
  
  apr_pool_destroy(pool);
  return 0;
}
