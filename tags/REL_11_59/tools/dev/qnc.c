/**
 * qsnc.c: Lightweight client/server utility which can be used 
 * to exchange data (strings) via UNIX-domain sockets.
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

/* system */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
/* socket */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

static void usage(const char *cmd, int code) {
  struct sockaddr_un addr;
  printf("usage: %s [-l] -U <path>\n", cmd);
  printf("\n");
  printf("Lightweight client/server utility which can be used to exchange data\n");
  printf("(strings) via UNIX-domain sockets. The client reads data from STDIN\n");
  printf("and sends it to the socket while the server (-l) is listening on the\n");
  printf("socket writing the received data to STDOUT.\n");
  printf("\n");
  printf("Options\n");
  printf(" -U <path>\n");
  printf("    Specifies the UNIX-domain socket path (max. %lu char).\n", sizeof(addr.sun_path)-1);
  printf(" -l\n");
  printf("    Used to specify that %s should listen for an incoming\n", cmd);
  printf("    message rather than initiate a connection and sending data.\n");
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  exit(code);
}

static int runsrv(int fd, struct sockaddr_un addr) {
  char buf[100];
  int cl, len;
  if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    fprintf(stderr, "ERROR: failed to bind to socket\n");
    return 1;
  }
  if(listen(fd, 5) == -1) {
    fprintf(stderr, "ERROR: failed to listen on socket\n");
    return 1;
  }
  if((cl = accept(fd, NULL, NULL)) == -1) {
    fprintf(stderr, "ERROR: accept error\n");
    return 1;
  }
  while((len=read(cl,buf,sizeof(buf))) > 0) {
    printf("%.*s", len, buf);
  }
  close(cl);
  return 0;
}

static int runcli(int fd, struct sockaddr_un addr) {
  char buf[100];
  int rc;
  if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    fprintf(stderr, "ERROR: failed to connect to socket\n");
    return 1;
  }
  while((rc=read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
    if(write(fd, buf, rc) != rc) {
      if(rc <= 0) {
	fprintf(stderr, "ERROR: failed to write data to socket\n");
	return 1;
      }
    }
  }
  return 0;
}

int main(int argc, const char *const argv[]) {
  const char *path = 0;
  int listen = 0;
  const char *cmd = strrchr(argv[0], '/');
  int fd;
  int rc = 0;
  struct sockaddr_un addr;

  if(cmd == NULL) {
    cmd = argv[0];
  } else {
    cmd++;
  }
  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-U") == 0) {
      if(--argc >= 1) {
	path = *(++argv);
      }
    } else if(strcmp(*argv,"-l") == 0) {
      listen = 1;
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(cmd, 0);
    }
    argc--;
    argv++;
  }

  if(path == NULL) {
    usage(cmd, 1);
  }

  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "ERROR: failed to create socket\n");
    return 1;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if(listen) {
    unlink(path);
    rc = runsrv(fd, addr);
  } else {
    rc = runcli(fd, addr);
  }

  return rc;
}
