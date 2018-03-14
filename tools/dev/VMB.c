/**
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

#define MAX 3
#define MSIZE 1048576

static const char revision[] = "$Revision$";

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
	  printf("model name: %s", v);
	}
      }
      if(strncasecmp(line, "bogomips", strlen("bogomips")) == 0) {
	line[strlen(line)-1] = '\0';
	if(lineNR == 1) {
	  char *v = strchr(line, ':');
	  lineNR++;
	  if(v) {
	    v++;
	    printf("bogimips:   %s", v);
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
}

static int add(int in) {
  return in + 1;
}

static void calc(const char *id) {
  char buff[] = "abcdefghABCDEFGXXXXXXXXXXXX123\n";
  char *p;

  char hx;
  int i, k;
  long long counter = 0;
  double d;
  
  for(i = 1; i < 10000000; i++) {
    counter++;
    p = strchr(buff, '1');
    k = atoi(p);
    counter = k * counter;
    if(i % 1000000 == 0) {
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
  char hx;
  int i;
  int maxSize = MSIZE;
  int inx = 0;
  char *ar[MAX];
  
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
    maxSize = atoi(*argv);
    argc--;
    argv++;
  }
  if(maxSize < MSIZE) {
    maxSize = MSIZE;
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
  printf("memory alloc/write %dx%d bytes (%dMB) ",
	 MAX, maxSize, (MAX*maxSize)/1024/1024);
  gettimeofday(&tv, NULL);
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  for(inx = 0; inx<MAX; inx++) {
    printf(".");
    fflush(stdout);
    ar[inx] = calloc(maxSize, sizeof(char));
  }
  for(inx = 0; inx<MAX; inx++) {
    char *c = ar[inx];
    int j;
    sprintf(c, "[%d]", inx);
    for(j = 3; j<maxSize-1; j++) {
      c[j] = 5;
    }
  }
  for(inx = 0; inx<MAX; inx++) {
    char *c = ar[inx];
    printf("%s", c);
    fflush(stdout);
    memset(c, maxSize-1, 1);
  }
  for(inx = 0; inx<MAX; inx++) {
    free(ar[inx]);
  }
  printf("\n");
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

  printf("========================\n");
  printf("memory:     %10lldms\n", memory);
  printf("processing: %10lldms\n", cpu);
  printf("========================\n");

  return 0;
}
