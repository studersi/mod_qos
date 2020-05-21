/**
 * Utilities for the quality of service module mod_qos.
 *
 * qsrotate.c: Log rotation tool.
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2020 Pascal Buchbinder
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
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>

#include <time.h>
#include <zlib.h>     

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "qs_util.h"

#define HUGE_STR       1024

//yyyy-mm-dd<sp>hh-mm-ss<sp>
#define TME_STR_LEN    20

/* global variables used by main and support thread */
static int m_force_rotation = 0;
static time_t m_tLogEnd = 0;
static time_t m_tRotation = 86400; /* default are 24h */
static int m_nLogFD = -1;
static int m_generations = -1;
static mode_t m_mode = 0660;
static char *m_file_name = NULL;
static long m_messages = 0;
static char *m_cmd = NULL;
static int m_compress = 0;
static int m_stdout = 0;
static int m_timestamp = 0;
static char time_string[TME_STR_LEN];
static long m_counter = 0;
static long m_limit = 2147483648 - (128 * 1024);
static int m_offset = 0;
static int m_offset_enabled = 0;

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
  qs_man_print(man, "%s - a log rotation tool (similar to Apache's rotatelogs).\n", cmd);
  printf("\n");
  if(man) {
    printf(".SH SYNOPSIS\n");
  }
  qs_man_print(man, "%s%s -o <file> [-s <sec> [-t <hours>]] [-b <bytes>] [-f] [-z] [-g <num>] [-u <name>] [-m <mask>] [-p] [-d]\n", man ? "" : "Usage: ", cmd);
  printf("\n");
  if(man) {
    printf(".SH DESCRIPTION\n");
  } else {
    printf("Summary\n");
  }
  qs_man_print(man, "%s reads from stdin (piped log) and writes the data to the provided\n", cmd);
  qs_man_print(man, "file rotating the file after the specified time.\n");
  printf("\n");
  if(man) {
    printf(".SH OPTIONS\n");
  } else {
    printf("Options\n");
  }
  if(man) printf(".TP\n");
  qs_man_print(man, "  -o <file>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Output log file to write the data to (use an absolute path).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -s <sec>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Rotation interval in seconds, default are 86400 seconds.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -t <hours>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Offset to UTC (enables also DST support), default is 0.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -b <bytes>\n");
  if(man) printf("\n");
  qs_man_print(man, "     File size limitation (default/max. are %ld bytes, min. are 1048576 bytes).\n", m_limit);
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -f\n");
  if(man) printf("\n");
  qs_man_print(man, "     Forced log rotation at the specified interval even no data is written.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -z\n");
  if(man) printf("\n");
  qs_man_print(man, "     Compress (gzip) the rotated file.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -g <num>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Generations (number of files to keep).\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -u <name>\n");
  if(man) printf("\n");
  qs_man_print(man, "     Become another user, e.g. www-data.\n");
  qs_man_print(man, "  -m <mask>\n");
  if(man) printf("\n");
  qs_man_print(man, "     File permission which is either 600, 640, 660 (default) or 664.\n");
  if(man) printf("\n.TP\n");
  qs_man_print(man, "  -p\n");
  if(man) printf("\n");
  qs_man_print(man, "     Writes data also to stdout (for piped logging).\n");
  qs_man_print(man, "  -d\n");
  if(man) printf("\n");
  qs_man_print(man, "     Line-by-line data reading prefixing every line with a timestamp.\n");
  printf("\n");
  if(man) {
    printf(".SH EXAMPLE\n");
  } else {
    printf("Example:\n");
  }
  qs_man_println(man, "  TransferLog \"|/usr/bin/%s -f -z -g 3 -o /var/log/apache/access.log -s 86400\"\n", cmd);
  printf("\n");
  qs_man_print(man, "The name of the rotated file will be /dest/filee.YYYYmmddHHMMSS\n");
  qs_man_print(man, "where YYYYmmddHHMMSS is the system time at which the data has been\n");
  qs_man_print(man, "rotated.\n");
  printf("\n");
  if(man) {
    printf(".SH NOTE\n");
  } else {
    printf("Notes:\n");
  }
  qs_man_println(man, " - Each %s instance must use an individual file.\n", cmd);
  qs_man_println(man, " - You may trigger a file rotation manually by sending the signal USR1\n");
  qs_man_print(man, "   to the process.\n");
  printf("\n");
  if(man) {
    printf(".SH SEE ALSO\n");
    printf("qsdt(1), qsexec(1), qsfilter2(1), qsgeo(1), qsgrep(1), qshead(1), qslog(1), qslogger(1), qsre(1), qsrespeed(1), qspng(1), qssign(1), qstail(1)\n");
    printf(".SH AUTHOR\n");
    printf("Pascal Buchbinder, http://mod-qos.sourceforge.net/\n");
  } else {
    printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  }
  if(man) {
    exit(0);
  } else {
    exit(1);
  }
}

static time_t get_now() {
  time_t now = time(NULL);
  if(m_offset_enabled) {
    struct tm lcl = *localtime(&now);
    if(lcl.tm_isdst) {
      now += 3600;
    }
    now += m_offset;
  }
  return now;
}

static int openFile(const char *cmd, const char *file_name) {
  int m_nLogFD = open(file_name, O_WRONLY | O_CREAT | O_APPEND, m_mode);
  /* error while opening log file */
  if(m_nLogFD < 0) {
    fprintf(stderr,"[%s]: ERROR, failed to open file <%s>\n", cmd, file_name);
  }
  return m_nLogFD;
}

/**
 * Compress method called by a child process (forked)
 * used to compress the rotated file.
 *
 * @param cmd Command name (used when logging errors)
 * @param arch Path to the file to compress. File gets renamed to <arch>.gz
 */
static void compressThread(const char *cmd, const char *arch) {
  gzFile *outfp;
  int infp;
  char dest[HUGE_STR+20];
  char buf[HUGE_STR];
  int len;
  snprintf(dest, sizeof(dest), "%s.gz", arch);
  /* low prio */
  if(nice(10) == -1) {
    fprintf(stderr, "[%s]: WARNING, failed to change nice value: %s\n", cmd, strerror(errno));
  }
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
  chmod(dest, m_mode);
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

void writeTimestamp() {
  time_t tm = time(NULL);
  struct tm *ptr = localtime(&tm);
  strftime(time_string, TME_STR_LEN, "%Y-%m-%d %H:%M:%S ", ptr);
  write(m_nLogFD, time_string, TME_STR_LEN);
}

/**
 * Rotates a file
 *
 * @param cmd Command name to be used in log messages
 * @param now
 * @param file_name Name of the file to rotate (rename)
 * @param messages Number of lines/buffers which had been read
 */
static void rotate(const char *cmd, time_t now,
		   const char *file_name, long *messages) {
  int rc;
  char arch[HUGE_STR+20];
  char tmb[20];
  struct tm *ptr = localtime(&now);
  strftime(tmb, sizeof(tmb), "%Y%m%d%H%M%S", ptr);
  snprintf(arch, sizeof(arch), "%s.%s", file_name, tmb);

  /* set next rotation time */
  m_tLogEnd = ((now / m_tRotation) * m_tRotation) + m_tRotation;
  // reset byte counter
  m_counter = 0;
  
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
      rc = ftruncate(m_nLogFD, 0);
      rc = write(m_nLogFD, msg, strlen(msg));
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
	  qs_deleteOldFiles(file_name, m_generations);
	}
	exit(0);
      }
    }
  }
}

/**
 * Separate thread which initiates file rotation even no
 * log data is written.
 *
 * @param argv (not used)
 */
static void *forcedRotationThread(void *argv) {
  time_t now;
  time_t n;
  while(1) {
    qs_csLock();
    now = get_now();
    if(now > m_tLogEnd) {
      rotate(m_cmd, now, m_file_name, &m_messages);
    }
    qs_csUnLock();
    now = get_now();
    n = 1 + m_tLogEnd - now;
    sleep(n);
  }
  return NULL;
}

void handle_signal1(int signal) {
  rotate(m_cmd, get_now(), m_file_name, &m_messages);
  return;
}

int main(int argc, char **argv) {
  char *username = NULL;
  int rc;
  char *buf;
  int nRead, nWrite;
  time_t now;
  struct stat st;
  long sizeLimit = 0;

  pthread_attr_t *tha = NULL;
  pthread_t tid;
  struct sigaction sa;
 
  char *cmd = strrchr(argv[0], '/');

  sa.sa_handler = &handle_signal1;
  sa.sa_flags = SA_RESTART;
   
  if(cmd == NULL) {
    cmd = argv[0];
  } else {
    cmd++;
  }
  m_cmd = calloc(1, strlen(cmd)+1);
  strcpy(m_cmd, cmd); // copy as we can't pass it when forking

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
    } else if(strcmp(*argv,"-t") == 0) {
      if (--argc >= 1) {
	m_offset = atoi(*(++argv));
	m_offset = m_offset * 3600;
	m_offset_enabled = 1;
      } 
    } else if(strcmp(*argv,"-g") == 0) {
      if (--argc >= 1) {
	m_generations = atoi(*(++argv));
      } 
    } else if(strcmp(*argv,"-b") == 0) {
      if (--argc >= 1) {
	sizeLimit = atol(*(++argv));
      } 
    } else if(strcmp(*argv,"-m") == 0) {
      if (--argc >= 1) {
	int mode = atoi(*(++argv));
	if(mode == 600) {
	  m_mode = 0600;
	} else if(mode == 640) {
	  m_mode = 0640;
	} else if(mode == 660) {
	  m_mode = 0660;
	} else if(mode == 664) {
	  m_mode = 0664;
	}
      } 
    } else if(strcmp(*argv,"-z") == 0) {
      m_compress = 1;
    } else if(strcmp(*argv,"-p") == 0) {
      m_stdout = 1;
    } else if(strcmp(*argv,"-d") == 0) {
      m_timestamp = 1;
      memset(time_string, 32, TME_STR_LEN);
    } else if(strcmp(*argv,"-f") == 0) {
      m_force_rotation = 1;
    } else if(strcmp(*argv,"-h") == 0) {
      usage(m_cmd, 0);
    } else if(strcmp(*argv,"--help") == 0) {
      usage(m_cmd, 0);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(m_cmd, 0);
    } else if(strcmp(*argv,"--man") == 0) {
      usage(m_cmd, 1);
    }

    argc--;
    argv++;
  }

  if(m_file_name == NULL) usage(m_cmd, 0);
  if(sizeLimit > 0 && sizeLimit < m_limit && sizeLimit >= (1024 * 1024)) {
    m_limit = sizeLimit;
  } else if(sizeLimit > 0 && sizeLimit < (1024 * 1024)) {
    m_limit = 1024 * 1024;
  }

  if(stat(m_file_name, &st) == 0) {
    m_counter = st.st_size;
  }

  sigaction(SIGUSR1, &sa, NULL);
  qs_setuid(username, m_cmd);
  
  /* set next rotation time */
  now = get_now();
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

  buf = calloc(1, MAX_LINE_BUFFER+1);
  for(;;) {
    if(m_timestamp) {
      // low perf line-by-line read
      if(fgets(buf, MAX_LINE_BUFFER, stdin) == NULL) {
	exit(3);
      } else {
	nRead = strlen(buf);
	if(m_force_rotation) {
	qs_csLock();                       // >@CTR1
      }
	m_counter += (nRead + TME_STR_LEN);
	now = get_now();
	writeTimestamp();
	nWrite = write(m_nLogFD, buf, nRead);
      }
    } else {
      // normal/fast buffer read/process
      nRead = read(0, buf, MAX_LINE_BUFFER);
      if(nRead == 0) exit(3);
      if(nRead < 0) if(errno != EINTR) exit(4);
      if(m_force_rotation) {
	qs_csLock();                         // >@CTR1
      }
      m_counter += nRead;
      now = get_now();
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
      m_messages++;
      if(nWrite != nRead) {
	if(m_nLogFD >= 0) {
	  char msg[HUGE_STR];
	  snprintf(msg, sizeof(msg), "ERROR while writing to file, %ld messages lost\n", m_messages);
	  /* error while writing data, try to delete the old file and continue ... */
	  rc = ftruncate(m_nLogFD, 0);
	  rc = write(m_nLogFD, msg, strlen(msg));
	  m_messages = 0;
	}
      }
    }
    // end buffer or line read
    if((now > m_tLogEnd) || (m_counter > m_limit)) {
      /* rotate! */
      rotate(m_cmd, now, m_file_name, &m_messages);
    }
    if(m_force_rotation) {
      qs_csUnLock();                         // <@CTR1
    }
  }
  memset(buf, 0, MAX_LINE_BUFFER);
  free(buf);
  return 0;
}
