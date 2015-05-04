/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2015 Pascal Buchbinder
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

static const char revision[] = "$Id: qs_util.c,v 1.18 2015-05-04 20:24:59 pbuchbinder Exp $";

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

#include "qs_util.h"

/* mutex for counter access */
static pthread_mutex_t m_qs_lock_cs;
/* online/offline mode */
static int m_qs_offline = 0;
/* internal clock for offline analysis
 * stores time in seconds */
static time_t m_qs_virtualSystemTime = 0;

/* ----------------------------------
 * functions
 * ---------------------------------- */

/**
 * man:
 * - escape special chars, like "\" and "-"
 * - wipe leading spaces
 * - wipe tailing LF
 */
void qs_man_print(int man, const char *fmt, ...) {
  char bufin[4096];
  char bufout[4096];
  va_list args;
  int i = 0;
  int j = 0;
  memset(bufin, 0, 4096);
  va_start(args, fmt);
  vsprintf(bufin, fmt, args);
  if(man) {
    // wipe leading spaces
    //    while(bufin[i] == ' ' && bufin[i+1] == ' ') {
    while(bufin[i] == ' ') {
      i++;
    }
  }
  while(bufin[i] && j < 4000) {
    // escape "\\" and "-" for man page
    if(man && (bufin[i] == '\\' || bufin[i] == '-')) {
      bufout[j] = '\\';
      j++;
    }
    if(bufin[i] == '\n') {
      if(man) {
	// skip LF for man page
	i++;
      } else {
	// keep LF
	bufout[j] = bufin[i];
	i++;
	j++;
      }
    } else {
      // standard char
      bufout[j] = bufin[i];
      i++;
      j++;
    }
  }
  bufout[j] = '\0';
  printf("%s", bufout);
  if(man) {
    printf(" ");
  }
}

// escape only
void qs_man_println(int man, const char *fmt, ...) {
  char bufin[4096];
  char bufout[4096];
  va_list args;
  int i = 0;
  int j = 0;
  memset(bufin, 0, 4096);
  va_start(args, fmt);
  vsprintf(bufin, fmt, args);
  while(bufin[i] && j < 4000) {
    // escape "\\" and "-" for man page
    if(man && (bufin[i] == '\\' || bufin[i] == '-')) {
      bufout[j] = '\\';
      j++;
    }
    // standard char
    bufout[j] = bufin[i];
    i++;
    j++;
  }
  bufout[j] = '\0';
  printf("%s", bufout);
}

char *qs_CMD(const char *cmd) {
  char *buf = calloc(1024, 1);
  int i = 0;
  while(cmd[i] && i < 1023) {
    buf[i] = toupper(cmd[i]);
    i++;
  }
  buf[i] = '\0';
  return buf;
}

/* io --------------------------------------------------------- */
/*
 * reads a line from stdin
 *
 * @param s Buffer to write line to
 * @param n Length of the buffer
 * @return 0 on EOF, or 1 if there is more data to read
 */
int qs_getLine(char *s, int n) {
  int i = 0;
  while (1) {
    s[i] = (char)getchar();
    if(s[i] == EOF) return 0;
    if (s[i] == CR) {
      s[i] = getchar();
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
      s[i] = '\0';
      return 1;
    }
    ++i;
  }
}

/*
 * reads a line from file
 *
 * @param s Buffer to write line to
 * @param n Length of the buffer
 * @return 0 on EOF, or 1 if there is more data to read
 */
int qs_getLinef(char *s, int n, FILE *f) {
  register int i = 0;
  while (1) {
    s[i] = (char) fgetc(f);
    if (s[i] == CR) {
      s[i] = fgetc(f);
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
      s[i] = '\0';
      return (feof(f) ? 1 : 0);
    }
    ++i;
  }
}

/* time ------------------------------------------------------- */
/*
 * We implement our own time which is either
 * the system time (real time) or the time from
 * the access log lines (offline) if m_qs_offline
 * has been set (use qs_set2OfflineMode() to enable
 * the offline mode).
 *
 * @param tme Set to the time since the Epoch in seconds.
 */
void qs_time(time_t *tme) {
  if(m_qs_offline) {
    /* use virtual time from the access log */
    *tme = m_qs_virtualSystemTime;
  } else {
    time(tme);
  }
}

/**
 * Sets time measurement (qs_time()) to offline mode.
 */
void qs_set2OfflineMode() {
  m_qs_offline = 1;
}

/* 
 * Updates the virtual time.
 */
void qs_setTime(time_t tme) {
  m_qs_virtualSystemTime = tme;
}

/* synchronisation -------------------------------------------- */
/*
 * locks all counter
 */
void qs_csLock() {
  pthread_mutex_lock(&m_qs_lock_cs);
}

/*
 * unlocks all counter
 */
void qs_csUnLock() {
  pthread_mutex_unlock(&m_qs_lock_cs);
}

/*
 * init locks
 */
void qs_csInitLock() {
  pthread_mutex_init(&m_qs_lock_cs, NULL);
}

/* logs ------------------------------------------------------- */

/**
 * Keeps only the specified number of files
 *
 * @param file_name Absolute file name
 * @param generations Number of files to keep
 */
void qs_deleteOldFiles(const char *file_name, int generations) {
  char dirname[QS_HUGE_STR];
  char *p;
  strcpy(dirname, file_name);
  p = strrchr(dirname, '/');
  if(strlen(file_name) > (QS_HUGE_STR - 10)) {
    // invalid file length
    return;
  }
  if(p) {
    DIR *dir;
    p[0] = '\0'; p++;
    dir = opendir(dirname);
    if(dir) {
      int num = 0;
      struct dirent *de;
      char filename[QS_HUGE_STR];
      snprintf(filename, sizeof(filename), "%s.20", p);
      /* determine how many files to delete */
      while((de = readdir(dir)) != 0) {
	if(de->d_name && (strncmp(de->d_name, filename, strlen(filename)) == 0)) {
	  num++;
	}
      }
      /* delete the oldest files (assumes they are ordered by their creation date) */
      while(num > generations) {
	char old[QS_HUGE_STR];
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
	  char unl[QS_HUGE_STR];
	  snprintf(unl, sizeof(unl), "%s/%s", dirname, old);
	  unlink(unl);
	}
	num--;
      }
      closedir(dir);
    }
  }
}

/* user ------------------------------------------------------- */
void qs_setuid(const char *username, const char *cmd) {
  if(username && getuid() == 0) {
    struct passwd *pwd = getpwnam(username);
    uid_t uid, gid;
    if(pwd == NULL) {
      fprintf(stderr, "[%s] unknown user id '%s': %s", cmd, username, strerror(errno));
      exit(1);
    }
    uid = pwd->pw_uid;
    gid = pwd->pw_gid;
    setgid(gid);
    setuid(uid);
    if(getuid() != uid) {
      fprintf(stderr, "[%s] setuid failed (%s,%d)", cmd, username, uid);
      exit(1);
    }
    if(getgid() != gid) {
      fprintf(stderr, "[%s] setgid failed (%d)", cmd, gid);
      exit(1);
    }
  }
}
