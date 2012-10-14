/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */
/**
 * Utilities for the quality of service module mod_qos.
 *
 * Shows the beginning of a log file stopping at the provided pattern.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2012 Pascal Buchbinder
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

static const char revision[] = "$Id: qshead.c,v 1.1 2012-09-19 18:48:51 pbuchbinder Exp $";

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <signal.h>

#include "qs_util.h"

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
  qs_man_print(man, "Utility reads from stdin and prints all lines to stdout until reaching the defined pattern.\n");
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -p <pattern>\n", man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, " %s reads lines from stdin and prints them to stdout unitl a line contains\n", cmd);
  qs_man_print(man, " the specified pattern (literal string).\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -p <pattern>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Search pattern (literal string).\n");
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qslog(1), qslogger(1), qspng(1), qsrotate(1), qssign(1) qstail(1)\n");
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

int main(int argc, const char * const argv[]) {
  char line[32768];
  const char *pattern = NULL;
  char *cmd = strrchr(argv[0], '/');
  int status = 0;
  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-p") == 0) {
      if (--argc >= 1) {
	pattern = *(++argv);
      } 
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 1);
    }
    argc--;
    argv++;
  }

  if(pattern == NULL) {
    usage(cmd, 0);
  }

  while(fgets(line, sizeof(line), stdin) != NULL) {
    printf("%s", line);
    if(strstr(line, pattern)) {
      return status;
    }
  }
  return status;
}
