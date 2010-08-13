
/**
 * Utilities for the quality of service module mod_qos.
 *
 * Log rotation tool.
 *
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2007-2010 Pascal Buchbinder
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

static const char revision[] = "$Id: qsrotate.c,v 2.7 2010-08-13 19:43:14 pbuchbinder Exp $";

#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>

#include <pthread.h>

#include <time.h>
#include <zlib.h>     

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "qs_util.h"

#define BUFSIZE        65536
#define HUGE_STR       1024

/* global variables used by main and support thread */
static int m_force_rotation = 0;
static time_t m_tLogEnd = 0;
static time_t m_tRotation = 86400; /* default are 24h */
static int m_nLogFD = -1;
static int m_generations = -1;
static char *m_file_name = NULL;
static long m_messages = 0;
static char *m_cmd = NULL;
static int m_compress = 0;
static int m_stdout = 0;

static void usage(char *cmd) {
  printf("\n");
  printf("Log rotation tool (similar to Apache's rotatelogs).\n");
  printf("\n");
  printf("Usage: %s -o <file> [-s <sec>] [-f] [-z] [-g <num>] [-u <name>] [-p]\n", cmd);
  printf("\n");
  printf("Summary\n");
  printf("Example:\n");
  printf("  TransferLog \"|%s -o /dest/file -s 86400\"\n", cmd);
  printf("The name of the rotated file will be /dest/filee.YYYYmmddHHMMSS\n");
  printf("where YYYYmmddHHMMSS is the system time at which the data has been\n");
  printf("rotated.\n");
  printf("\n");
  printf("Options\n");
  printf("  -o <file>\n");
  printf("     Output log file to write the data to.\n");
  printf("  -s <sec>\n");
  printf("     Rotation interval in seconds, default are 86400 seconds.\n");
  printf("  -f\n");
  printf("     Forced log rotation even no data is written.\n");
  printf("  -z\n");
  printf("     Compress (gzip) the rotated file.\n");
  printf("  -g <num>\n");
  printf("     Generations (number of files to keep).\n");
  printf("  -u <name>\n");
  printf("     Become another user, e.g. www-data.\n");
  printf("  -p\n");
  printf("     Writes data also to stdout (for piped logging).\n");
  printf("\n");
  printf("Note\n");
  printf("  - Each %s instance must use an individual file!\n", cmd);
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  exit(1);
}

static int openFile(const char *cmd, const char *file_name) {
  int m_nLogFD = open(file_name, O_WRONLY | O_CREAT | O_APPEND, 0660);
  /* error while opening log file */
  if(m_nLogFD < 0) {
    fprintf(stderr,"[%s]: ERROR, failed to open file <%s>\n", cmd, file_name);
  }
  return m_nLogFD;
}

static void deleteOldFiles(const char *cmd, const char *file_name) {
  char dirname[HUGE_STR];
  char *p;
  strcpy(dirname, file_name);
  p = strrchr(dirname, '/');
  if(p) {
    DIR *dir;
    p[0] = '\0'; p++;
    dir = opendir(dirname);
    if(dir) {
      int num = 0;
      struct dirent *de;
      char filename[HUGE_STR];
      snprintf(filename, sizeof(filename), "%s.20", p);
      /* determine how many files to delete */
      while((de = readdir(dir)) != 0) {
	if(de->d_name && (strncmp(de->d_name, filename, strlen(filename)) == 0)) {
	  num++;
	}
      }
      /* delete the oldes files */
      while(num > m_generations) {
	char old[HUGE_STR];
	old[0] = '\0';
	rewinddir(dir);
	while((de = readdir(dir)) != 0) {
	  if(de->d_name && (strncmp(de->d_name, filename, strlen(filename)) == 0)) {
	    if(strcmp(old, de->d_name) > 0) {
	      snprintf(old, sizeof(old), "%s", de->d_name);
	    } else {
	      if(old[0] == '\0') {
		snprintf(old, sizeof(old), "%s", de->d_name);
	      }
	    }
	  }
	}
	{
	  /* build abs path and delete it */
	  char unl[HUGE_STR];
	  snprintf(unl, sizeof(unl), "%s/%s", dirname, old);
	  unlink(unl);
	}
	num--;
      }
      closedir(dir);
    }
  }
}

static void compressThread(const char *cmd, const char *arch) {
  gzFile *outfp;
  int infp;
  char dest[HUGE_STR+20];
  char buf[HUGE_STR];
  int len;
  snprintf(dest, sizeof(dest), "%s.gz", arch);
  /* low prio */
  nice(10);
  if((infp = open(arch, O_RDONLY)) == -1) {
    /* failed to open file, can't compress it */
    fprintf(stderr,"[%s]: ERROR, could not open file for compression <%s>\n", cmd, arch);
    return;
  }
  if((outfp = gzopen(dest,"wb")) == NULL) {
    fprintf(stderr,"[%s]: ERROR, could not open file for compression <%s>\n", cmd, dest);
    close(infp);
    return;
  }
  while((len = read(infp, buf, sizeof(buf))) > 0) {
    gzwrite(outfp, buf, len);
  }
  gzclose(outfp);
  close(infp);
  /* done, delete the old file */
  unlink(arch);
}

void sigchild(int signo) {
  pid_t pid;
  int stat;   
  while((pid=waitpid(-1,&stat,WNOHANG)) > 0) {
  }
}

static void rotate(const char *cmd, const char *file_name, long *messages) {
  char arch[HUGE_STR+20];
  char tmb[20];
  time_t now = time(NULL);
  struct tm *ptr = localtime(&now);
  strftime(tmb, sizeof(tmb), "%Y%m%d%H%M%S", ptr);
  snprintf(arch, sizeof(arch), "%s.%s", file_name, tmb);
  /* set next rotation time */
  m_tLogEnd = ((now / m_tRotation) * m_tRotation) + m_tRotation;
  
  /* rename current file */
  if(m_nLogFD >= 0) {
    close(m_nLogFD);
    rename(file_name, arch);
  }
  
  /* open new file */
  m_nLogFD = openFile(cmd, file_name);
  if(m_nLogFD < 0) {
    /* opening a new file has failed!
       try to reopen and clear the last file */
    char msg[HUGE_STR];
    snprintf(msg, sizeof(msg), "ERROR while writing to file, %ld messages lost\n", *messages);
    fprintf(stderr,"[%s]: ERROR, while writing to file <%s>\n", cmd, file_name);
    rename(arch,  file_name);
    m_nLogFD = openFile(cmd, file_name);
    if(m_nLogFD > 0) {
      ftruncate(m_nLogFD, 0);
      write(m_nLogFD, msg, strlen(msg));
    }
  } else {
    *messages = 0;
    if(m_compress || (m_generations != -1)) {
      signal(SIGCHLD,sigchild);
      if(fork() == 0) {
	if(m_compress) {
	  compressThread(cmd, arch);
	}
	if(m_generations != -1) {
	  deleteOldFiles(cmd, file_name);
	}
	exit(0);
      }
    }
  }
}

static void *forcedRotationThread(void *argv) {
  time_t now;
  time_t n;
  while(1) {
    qs_csLock();
    now = time(NULL);
    if(now > m_tLogEnd) {
      rotate(m_cmd, m_file_name, &m_messages);
    }
    qs_csUnLock();
    now = time(NULL);
    n = 1 + m_tLogEnd - now;
    sleep(n);
  }
}

int main(int argc, char **argv) {
  char *username = NULL;

  char buf[BUFSIZE];
  int nRead, nWrite;
  time_t now;

  pthread_attr_t *tha = NULL;
  pthread_t tid;

  char *m_cmd = strrchr(argv[0], '/');

  if(m_cmd == NULL) {
    m_cmd = argv[0];
  } else {
    m_cmd++;
  }
  
  while(argc >= 1) {
    if(strcmp(*argv,"-o") == 0) {
      if (--argc >= 1) {
	m_file_name = *(++argv);
      }
    } else if(strcmp(*argv,"-u") == 0) {
      if (--argc >= 1) {
	username = *(++argv);
      }
    } else if(strcmp(*argv,"-s") == 0) {
      if (--argc >= 1) {
	m_tRotation = atoi(*(++argv));
      } 
    } else if(strcmp(*argv,"-g") == 0) {
      if (--argc >= 1) {
	m_generations = atoi(*(++argv));
      } 
    } else if(strcmp(*argv,"-z") == 0) {
      m_compress = 1;
    } else if(strcmp(*argv,"-p") == 0) {
      m_stdout = 1;
    } else if(strcmp(*argv,"-f") == 0) {
      m_force_rotation = 1;
    }

    argc--;
    argv++;
  }

  if(m_file_name == NULL) usage(m_cmd);

  if(username && getuid() == 0) {
    struct passwd *pwd = getpwnam(username);
    uid_t uid, gid;
    if(pwd == NULL) {
      fprintf(stderr,"[%s]: ERROR, unknown user id %s\n", m_cmd, username);
      exit(1);
    }
    uid = pwd->pw_uid;
    gid = pwd->pw_gid;
    setgid(gid);
    setuid(uid);
    if(getuid() != uid) {
      fprintf(stderr,"[%s]: ERROR, setuid failed (%s,%d)\n", m_cmd, username, uid);
      exit(1);
    }
    if(getgid() != gid) {
      fprintf(stderr,"[%s]: ERROR, setgid failed (%d)\n", m_cmd, gid);
      exit(1);
    }
  }
  
  /* set next rotation time */
  now = time(NULL);
  m_tLogEnd = ((now / m_tRotation) * m_tRotation) + m_tRotation;
  /* open file */
  m_nLogFD = openFile(m_cmd, m_file_name);
  if(m_nLogFD < 0) {
    /* startup did not success */
    exit(2);
  }

  if(m_force_rotation) {
    qs_csInitLock();
    pthread_create(&tid, tha, forcedRotationThread, NULL);
  }

  for(;;) {
    nRead = read(0, buf, sizeof buf);
    if(nRead == 0) exit(3);
    if(nRead < 0) if(errno != EINTR) exit(4);
    if(m_force_rotation) {
      qs_csLock();
    }
    now = time(NULL);
    /* write data if we have a file handle (else continue but drop log data,
       re-try to open the file at next rotation time) */
    if(m_nLogFD >= 0) {
      do {
	nWrite = write(m_nLogFD, buf, nRead);
	if(m_stdout) {
	  printf("%.*s", nRead, buf);
	}
      } while (nWrite < 0 && errno == EINTR);
    }
    if(nWrite != nRead) {
      m_messages++;
      if(m_nLogFD >= 0) {
	char msg[HUGE_STR];
	snprintf(msg, sizeof(msg), "ERROR while writing to file, %ld messages lost\n", m_messages);
	/* error while writing data, try to delete the old file and continue ... */
	ftruncate(m_nLogFD, 0);
	write(m_nLogFD, msg, strlen(msg));
      }
    } else {
      m_messages++;
    }
    if(now > m_tLogEnd) {
      /* rotate! */
      rotate(m_cmd, m_file_name, &m_messages);
    }
    if(m_force_rotation) {
      qs_csUnLock();
    }
  }
  return 0;
}

