/**
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2021 Pascal Buchbinder
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

/* gcc -o VMB -pthread -O3 VMB.c
 *
 * Intel Xeon E5630 @2.53GHz (8x5054.31):    VMBc 206
 * AMD Sempron(tm) 145 800MHz (1x5624.46):   VMBc 127
 * Intel Core i3-2367M @1.40GHz (4x2793.87): VMBc 111
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

#define MAX 2
#define MSIZE 134217728

static const char revision[] = "$Revision$";

typedef struct {
  const char *print;
  const char *name;
} mem_t;

static const mem_t mem_param[] = {
  { "MemTotal:          ", "MemTotal:" },
  { "MemFree:           ", "MemFree:" },
  { "MemAvailable:      ", "MemAvailable:" },
  { "Buffers:           ", "Buffers:" },
  { "Cached:            ", "Cached:" },
  { NULL, NULL }
};

// e.g. "SwapFree:        3868164 kB"
static long lvalue(char *line) {
  long value = 0;
  char *p = line;
  while(p[0] && (p[0] < 48 || p[0] > 57)) {
    p++;
  }
  if(p[0]) {
    char *e = strchr(p, ' ');
    if(e) {
      e[0] = '\0';
      value = atol(p);
    }
  }
  return value;
}

static void pinfo() {
  FILE *file;
  char fname[1024];
  sprintf(fname, "/proc/%d/stat", getpid());
  file = fopen(fname, "r");
  if(file) {
    char line[1024];
    if(fgets(line, 1023, file) != NULL) {
      int i;
      char *p = line;
      char *end;
      for(i = 0; i<11; i++) {
	p = strchr(p, ' ');
	if(p == NULL) {
	  return;
	}
	p++;
      }
      end = strchr(p, ' ');
      if(end) {
	end[0] = '\0';
	/* major page faults (postition 12 of stat file)
	   Occurs when the system has to synchronize mem buffers 
	   with the disk, swap memory of other processes, or requires
	   IO to free memory. Happens for references of virtual memory
	   that has no physical page allocated to it.
	   => memory allocation was required which increased VMB latency. */
	printf("major page faults: %s\n", p);
      }
    }
    fclose(file);
  }
  return;
}

static void minfo() {
  FILE *file;
  
  file = fopen("/proc/meminfo", "r");
  if(file) {
    long total = 0;
    long free = 0;
    int lineNR=0;
    char line[1024];
    while(fgets(line, 1023, file) != NULL) {
      const mem_t *m = mem_param;
      if(strncasecmp(line, "SwapFree:", strlen("SwapFree:")) == 0) {
	free = lvalue(line);
      }
      if(strncasecmp(line, "SwapTotal:", strlen("SwapTotal:")) == 0) {
	total = lvalue(line);
      }
      while(m->name) {
	if(strncasecmp(line, m->name, strlen(m->name)) == 0) {
	  long value = lvalue(line);
	  printf("%s%ld\n", m->print, value);
	}
	m++;
      }
    }
    fclose(file);
    if(total > 0) {
      printf("used swap:         %ld\n", total - free);
    }
  }
  return;
}

static void cinfo() {
  FILE *file;
  
  file = fopen("/proc/cpuinfo", "r");
  if(file) {
    int lineNR=0;
    char line[1024];
    while(fgets(line, 1023, file) != NULL) {
      if(lineNR == 0 && strncasecmp(line, "model name", strlen("model name")) == 0) {
	char *v = strchr(line, ':');
	lineNR++;
	if(v) {
	  v++;
	  printf("model name:       %s", v);
	}
      }
      if(strncasecmp(line, "bogomips", strlen("bogomips")) == 0) {
	line[strlen(line)-1] = '\0';
	if(lineNR == 1) {
	  char *v = strchr(line, ':');
	  lineNR++;
	  if(v) {
	    v++;
	    printf("bogimips:         %s", v);
	  }
	} else {
	  char *v = strchr(line, ':');
	  if(v) {
	    v++;
	    printf("%s", v);
	  }
	}
      }
    }
    fclose(file);
    printf("\n");
  }
  return;
}


static void eightK(int maxSize) {
  int inx,j;
  int number = (maxSize - 1048576)/8192/2;
  char *ar[number];
  if(number < 0) {
    return;
  }
  printf("memory alloc/write %dx%d bytes (%dMB) ", number, 8192, number*8192/1024/1024);
  printf("a");
  for(inx = 0; inx<number; inx++) {
    ar[inx] = calloc(8192, sizeof(char));
  }
  printf("w");
  for(inx = 0; inx<number; inx++) {
    char *c = ar[inx];
    for(j = 0; j<8100; j++) {
      c[j] = 65;
    }
  }
  printf("r");
  for(inx = 0; inx<number; inx++) {
    char *c = ar[inx];
    j = strlen(c);
    c[j] = '\0';
  }
  printf("f");
  for(inx = 0; inx<number; inx++) {
    free(ar[inx]);
  }
  printf("\n");
}

static void cmem(int number, int maxSize) {
  int inx = 0;
  char *ar[number];
  
  printf("memory alloc/write %dx%d bytes (%dMB) ",
	 number, maxSize, (number*maxSize)/1024/1024);

  for(inx = 0; inx<number; inx++) {
    printf(".");
    fflush(stdout);
    ar[inx] = calloc(maxSize, sizeof(char));
  }
  for(inx = 0; inx<number; inx++) {
    char *c = ar[inx];
    int j;
    sprintf(c, "[%d]", inx);
    // write the block
    for(j = 4; j<maxSize-1; j++) {
      c[j] = 55;
    }
    // read the block
    j = strlen(&c[4]);
    c[j] = '\0';
  }
  for(inx = 0; inx<number; inx++) {
    char *c = ar[inx];
    printf("%s", c);
    fflush(stdout);
    memset(c, maxSize-1, 1);
  }
  for(inx = 0; inx<number; inx++) {
    free(ar[inx]);
  }
  printf("\n");
}

static int add(int in) {
  return in + 1;
}

static void calc(const char *id) {
  char buff[] = "abcdefghABCDEFGXXXXXXXXXXXX123\n";
  char *p;
  char str[256];
  int r;

  char hx;
  int i, k;
  long long counter = 0;
  double d;
  
  for(i = 1; i < 10000000; i++) {
    if(i%2 == 0) {
      sprintf(str, "%d", i);
      r = atoi(str);
    } else {
      r = i;
    }
    counter++;
    p = strchr(buff, '1');
    k = atoi(p);
    counter = k * counter;
    if(r % 1000000 == 0) {
      fflush(stdout);
      printf("%s", id);
    }
    if(counter > 1000000) {
      counter = counter - 100000;
    } else {
      counter = counter * 2;
    }
    for(k = 1; k <15; k++) {
      int t = (k%i) & counter;
      counter = counter - t;
      counter = counter / k;
    }
    for(k = 1; k <15; k++) {
      hx = (counter + k) & 0xff;
      hx = hx >> 1;
      hx = hx + add(hx);
      counter = counter + hx;
    }
    d = 1;
    for(k = 1; k <15; k++) {
      d = d + 0.2;
      if((d * 10 / 10) == d) {
	d = 1;
      }
    }
  }
  printf("%lld", counter+8);
}

static void *calcThread(void *argv) {
  char *ret = malloc(10);
  strcpy(ret, ">OK");
  calc("/");
  pthread_exit((void*)ret);
}

int main(int argc, const char *const argv[]) {
  int maxSize = MSIZE;
  int number = MAX;
  
  double av[3];
  char hostname[1024];
  char timeBuff[64];
  struct timeval tv;
  struct tm* tm_info;
  long long start, end, memory, cpu;

  pthread_attr_t *tha = NULL;
  pthread_t tid;
  char *ret;
  
  argv++;
  argc--;
  while(argc >= 1) {
    if(strcmp(*argv,"-s") == 0) {
      if (--argc >= 1) {
	maxSize = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-n") == 0) {
      if (--argc >= 1) {
	number = atoi(*(++argv));
      }
    } else if(strcmp(*argv,"-h") == 0) {
      printf("Usage: VMB [-s <size>] [-n <2..9>]\n");
      exit(1);
    }
    argc--;
    argv++;
  }
  if(maxSize < 8192) {
    maxSize = 8192;
  }
  if(number < 2 || number > 9) {
    number = MAX;
  }

  printf("========================\n");
  gettimeofday(&tv, NULL);
  tm_info = localtime(&tv.tv_sec);
  strftime(timeBuff, 26, "%Y:%m:%d %H:%M:%S", tm_info);
  gethostname(hostname, 1023);
  printf("VMB@%s %s %s\n", hostname, timeBuff, revision);
  getloadavg(av, 3);
  printf("load average: %.2f %.2f %.2f\n", av[0], av[1], av[2]);
  
  // alloc and write memory
  gettimeofday(&tv, NULL);
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  eightK(maxSize);
  cmem(number, maxSize);
  gettimeofday(&tv, NULL);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  memory = (end - start)/1000;

  // just some bogus operations...
  printf("generic operations ");
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  gettimeofday(&tv, NULL);
  pthread_create(&tid, tha, calcThread, NULL);
  calc("\\");
  pthread_join(tid, (void**)&ret);
  gettimeofday(&tv, NULL);
  printf("%s\n", ret);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  cpu = (end - start)/1000;
  
  cinfo();
  minfo();
  pinfo();
  
  printf("========================\n");
  printf("memory:     %10lldms\n", memory);
  printf("processing: %10lldms\n", cpu);
  if(maxSize == MSIZE && number == MAX) {
    printf("VMBc index: %10lld\n", (100000/cpu) + (30000/memory));
  }
  printf("========================\n");

  return 0;
}
