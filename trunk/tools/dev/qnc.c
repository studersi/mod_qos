/**
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2016 Pascal Buchbinder
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

static const char revision[] = "$Id: qnc.c,v 1.2 2016-12-07 14:43:58 pbuchbinder Exp $";

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
  printf("usage: %s [-l] -U <path>\n", cmd);
  printf("\n");
  printf("Lightweight client/server utility which can be used to exchange data\n");
  printf("(strings) via UNIX-domain sockets. The client reads data from STDIN\n");
  printf("and sends it to the socket while the server (-l) is listening on the\n");
  printf("socket writing the received data to STDOUT.\n");
  printf("\n");
  printf("Options\n");
  printf(" -U <path>\n");
  printf("    Specifies the UNIX-domain socket.\n");
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
