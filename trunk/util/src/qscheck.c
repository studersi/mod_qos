/**
 * Utilities for the quality of service module mod_qos.
 *
 * qscheck.c: Monitor testing tcp connectivity to servers used by mod_proxy.
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "qs_util.h"

//#include <config.h>

#define CR 13
#define LF 10
#define QS_TIMEOUT 2
#define QS_PROXYP "proxypass "
#define QS_PROXYP_TAB "proxypass\t"
#define QS_PROXYPR "proxypassreverse "
#define QS_PROXYPR_TAB "proxypassreverse\t"
#define QS_PROXYR "proxyremote "
#define QS_PROXYR_TAB "proxyremote\t"
#define QS_INCLUDE "nclude "
#define QS_INCLUDE_TAB "nclude\t"
#define QS_SERVERROOT "ServerRoot "
#define QS_SERVERROOT_TAB "ServerRoot\t"

static int m_verbose = 0;
static char ServerRoot[1024];
static char *checkedHosts = NULL;

/**
 * Prints usage text
 */
static void usage(char *cmd) {
  printf("\n");
  printf("Monitor programm testing the TCP connectivity to servers.\n");
  printf("\n");
  printf("Usage: %s -c <httpd.conf> [-v]\n", cmd);
  printf("\n");
  printf("Verifies the connectivity to the server referred either\n");
  printf("by the ProxyPass, ProxyPassReverse, or ProxyReverse\n");
  printf("directive used by mod_proxy.\n");
  printf("\n");
  printf("You may alternatively use \"%s -i <hostname>:<port>\" if\n", cmd);
  printf("you want to check the TCP connectivity to a single host.\n");
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  exit(1);
}

/**
 * Opens a tcp connection
 */
static int ping(unsigned long address, int port) {
  int status = 0;
  struct sockaddr_in addr;
  int skt;
  addr.sin_addr.s_addr = address;
  addr.sin_port = htons(port);
  addr.sin_family = PF_INET;
  skt = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(skt != -1) {
    int sflags = fcntl(skt,F_GETFL,0);
    if(sflags >=0) {
      /* set non blocking socket */
      if(fcntl(skt,F_SETFL,sflags|O_NONBLOCK) >=0) {
	/* this connect returns immediately */
	int ret = connect(skt, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
	if(fcntl(skt,F_SETFL,sflags) >=0) {
	  socklen_t lon = sizeof(int); 
	  int valopt;
	  fd_set fd_w;
	  struct timeval tme;
	  tme.tv_sec = QS_TIMEOUT;
	  tme.tv_usec = 0;
	  FD_ZERO(&fd_w);
	  FD_SET(skt, &fd_w);
	  /* select returns -1 on timeout, else 1 (connected or refused) */
	  if(select(FD_SETSIZE, NULL, &fd_w, NULL, &tme) > 0) {
	    /* check the status of the socket in order to distinguish between
	       connected or refused */
	    if(getsockopt(skt, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) >= 0) {
	      if(!valopt) {
		/* UP ! */
		status = 1;
	      }
	    }
	  }
	}
      }
    }
  }
  return status;
}

/**
 * resolves host address
 */
static unsigned long getAddress(const char *hostname) {
  int ip = 1;
  int i = 0;
  unsigned long address = 0L;
  struct hostent *hoste;
  for(i = 0; i < (int) strlen(hostname); i++) {
    if((!isdigit((int) hostname[i])) && (hostname[i] != '.')) {
      ip = 0;
      break;
    }
  }
  if (ip) {
    address = inet_addr(hostname);
    if(address == -1) {
      return 0L;
    }
  } else {
    hoste = gethostbyname(hostname);
    if (!hoste || !hoste->h_addr_list[ 0 ]) {
      /* can't resolve host name */
      return 0L;
    }
    address = ((struct in_addr*)hoste->h_addr_list[ 0 ])->s_addr;
  }
  return address;
}

/*
 * Checks a single host (parse host string, resolve address, ping).
 */
static int checkHost(const char *cmd, const char *filename, int ln, char *abs_url) {
  int status = 1;
  char *schema = abs_url;
  char *host = NULL;
  char *ports = NULL;
  int port = 0;
  char hp[1024];
  unsigned long address;
  char *x = strstr(abs_url, "://");
  if(x == NULL) {
    if(m_verbose) {
      fprintf(stderr,"[%s]: ERROR, wrong syntax <%s> in %s on line %d\n",
	      cmd, abs_url, filename, ln);
    }
    return 0;
  }
  x[0] = '\0'; x = x + strlen("://");
  host = x;
  ports = strchr(x, ':');
  if(ports != NULL) {
    ports[0] = '\0'; ports++;
    x = strchr(ports, '/');
    if(x == NULL) {
      int i;
      x = ports;
      for(i=0;(x[i] != ' ') && (x[i] != '\t') && (x[i] != '\0'); i++);
      x[i] = '\0';
    } else {
      x[0] = '\0';
    }
    port = atoi(ports);
  } else {
    ports = strchr(x, '/');
    if(ports == NULL) {
      int i;
      for(i=0;(x[i] != ' ') && (x[i] != '\t') && (x[i] != '\0'); i++);
      x[i] = '\0';
    } else {
      ports[0] = '\0';
    }
    if(strcmp(schema, "http") == 0) {
      port = 80;
    } else {
      port = 443;
    }
  }
  /* check each host only once */
  snprintf(hp, sizeof(hp), "#%s:%d#", host, port);
  if(checkedHosts && strstr(checkedHosts, hp) != NULL) {
    /* already checked */
    return 1;
  }
  if(checkedHosts == NULL) {
    checkedHosts = calloc(1, strlen(hp) + 1);
    strcpy(checkedHosts, hp);
  } else {
    int pl = strlen(checkedHosts) +strlen(hp) + 1;
    char *p = calloc(1, pl);
    snprintf(p, pl, "%s%s", checkedHosts, hp);
    free(checkedHosts);
    checkedHosts = p;
  }
  /* resolve address */
  address = getAddress(host);
  if(address == 0L) {
    fprintf(stderr,"[%s]: ERROR, could not resolve hostname %s\n", cmd, host);
    return -1;
  }
  /* check connection */
  if(ping(address, port)) {
    if(m_verbose) {
      printf("[%s]: %s:%d Up\n", cmd, host, port);
    }
    return 1;
  } else {
    printf("[%s]: %s:%d Down\n", cmd, host, port);
    return 0;
  }
}

/**
 * Open file and check every ProxyPass* or ProxyR* entry.
 * - follows include ... directive
 * - determines serverroot
 */
static int checkFile(const char *cmd, const char *filename) {
  int status = 1;
  int ln = 0;
  char line[1024];
  FILE *f = fopen(filename, "r");
  if(f == NULL) {
    if(ServerRoot[0] != '\0') {
      char fqfile[2048];
      snprintf(fqfile, sizeof(fqfile), "%s/%s", ServerRoot, filename);
      f = fopen(fqfile, "r");
    }
  }
  if(f == NULL) {
    fprintf(stderr,"[%s]: ERROR, could not open file %s\n", cmd, filename);
    return 0;
  }

  while(!qs_getLinef(line, sizeof(line), f)) {
    char *command = NULL;
    int cmd_len = 0;
    int to = 0;
    while(line[to]) {
      line[to] = tolower(line[to]);
      to++;
    }
    ln++;
    command = strstr(line, QS_PROXYP);
    cmd_len = strlen(QS_PROXYP);
    if(command == NULL) command = strstr(line, QS_PROXYP_TAB);
    if(command == NULL) {
      command = strstr(line, QS_PROXYPR);
      cmd_len = strlen(QS_PROXYPR);
    }
    if(command == NULL) command = strstr(line, QS_PROXYPR_TAB);
    if(command == NULL) {
      command = strstr(line, QS_PROXYR);
      cmd_len = strlen(QS_PROXYR);
    }
    if(command == NULL) command = strstr(line, QS_PROXYR_TAB);
    if(command && strchr(line, '#') == 0) {
      /* command = cmd url schema://host[:port]/url */
      char *abs_url = &command[cmd_len];
      int i, j;

      /* get the url */
      for(i=0;(abs_url[i] == ' ') || (abs_url[i] == '\t'); i++);
      abs_url = &abs_url[i];

      /* skip url */
      for(i=0;(abs_url[i] != ' ') && (abs_url[i] != '\t') && (abs_url[i] != '\0'); i++);
      abs_url = &abs_url[i];

      /* get schema://host[:port]/url */
      for(i=0;(abs_url[i] == ' ') || (abs_url[i] == '\t'); i++);
      abs_url = &abs_url[i];

      /* ping */
      if(abs_url && abs_url[0] != '\0' && abs_url[0] != '!') {
	status = status & checkHost(cmd, filename, ln, abs_url);
      }
    } else {
      /* include commands */
      command = strstr(line, QS_INCLUDE);
      if(command == NULL) command = strstr(line, QS_INCLUDE_TAB);
      if(command && strchr(line, '#') == 0) {
	char *file = &command[strlen(QS_INCLUDE)];
	int i, j;
	/* get the value */
	for(i=0;(file[i] == ' ') || (file[i] == '\t'); i++);
	/* delete spaces at the end of the value */
	if(&file[i] != '\0') {
	  for(j=i+1;(file[j] != ' ') && (file[j] != '\t') && (file[j] != '\0'); j++);
	  file[j] = '\0';
	}
	file = &file[i];
	status = status & checkFile(cmd, file);
      } else {
	/* server root */
	command = strstr(line, QS_SERVERROOT);
	if(command == NULL) command = strstr(line, QS_SERVERROOT_TAB);
	if(command && strchr(line, '#') == 0) {
	  char *sr = &command[strlen(QS_SERVERROOT)];
	  int i, j;
	  /* get the value */
	  for(i=0;(sr[i] == ' ') || (sr[i] == '\t'); i++);
	  /* delete spaces at the end of the value */
	  if(&sr[i] != '\0') {
	    for(j=i+1;(sr[j] != ' ') && (sr[j] != '\t') && (sr[j] != '\0'); j++);
	    sr[j] = '\0';
	  }
	  strcpy(ServerRoot, &sr[i]);
	}
      }
    }
  }
  fclose(f);
  return status;
}

int main(int argc, char **argv) {
  char *config = NULL;
  char *cmd = strrchr(argv[0], '/');
  char *single = NULL;
  int status = 1;
  if(cmd == NULL) {
    cmd = argv[0];
  } else {
    cmd++;
  }
  ServerRoot[0] = '\0';
  while(argc >= 1) {
    if(strcmp(*argv,"-c") == 0) {
      if (--argc >= 1) {
	config = *(++argv);
      }
    } else if(strcmp(*argv,"-i") == 0) {
      if (--argc >= 1) {
	single = *(++argv);
      }
    } else if(strcmp(*argv,"-v") == 0) {
      m_verbose = 1;
    }
    argc--;
    argv++;
  }
  if(single) {
    char *hostName = single;
    char *portNumber = strchr(single, ':');
    if(portNumber) {
      unsigned long addr;
      int prt;
      portNumber[0] = '\0';
      portNumber++;
      addr = getAddress(hostName);
      prt = atoi(portNumber);
      if(addr && prt) {
	if(ping(addr, prt)) {
	  if(m_verbose) {
	    printf("[%s]: %s:%d Up\n", cmd, hostName, prt);
	  }
	  status = 1;
	} else {
	  printf("[%s]: %s:%d Down\n", cmd, hostName, prt);
	  status = 0;
	}
      } else {
	// could not resolve
	fprintf(stderr,"[%s]: ERROR, unknown host/port\n", cmd); 
	status = 0;
      }
    } else {
      // invalid input
      fprintf(stderr,"[%s]: ERROR, invalid format\n", cmd); 
      status = 0;
    }
  } else {
    if(config == NULL) {
      usage(cmd);
    }
    status = checkFile(cmd, config);
  }
  if(status == 0) {
    fprintf(stderr,"[%s]: ERROR, check failed\n", cmd);
    exit(1);
  }
  printf("[%s]: OK, check successful\n", cmd);
  return 0;
}
