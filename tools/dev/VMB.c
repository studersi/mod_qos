
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#define MAX 2
#define MSIZE 1048576

static const char revision[] = "$Revision$";

int main(int argc, const char *const argv[]) {
  char hx;
  int i, k;
  int maxSize = MSIZE;
  int inx = 0;
  long long counter = 0;
  char *ar[MAX];
  double d;
  
  char buff[] = "abcdefghABCDEFGXXXXXXXXXXXX123\n";
  char *p;

  char hostname[1024];
  char timeBuff[64];
  struct timeval tv;
  struct tm* tm_info;
  long long start, end, memory, cpu;
  
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
  for(i = 1; i < 10000000; i++) {
    counter++;
    p = strchr(buff, '1');
    k = atoi(p);
    counter = k * counter;
    if(i % 1000000 == 0) {
      fflush(stdout);
      printf(".");
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

  gettimeofday(&tv, NULL);
  printf("%lld\n", counter+100);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  cpu = (end - start)/1000;
  
  printf("========================\n");
  printf("memory:     %10lldms\n", memory);
  printf("processing: %10lldms\n", cpu);
  printf("========================\n");
	 
  return 0;
}
