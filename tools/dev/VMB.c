
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#define MAX 2
#define MSIZE 1048576

int main(int argc, const char *const argv[]) {
  int i, k;
  int maxSize = MSIZE;
  int inx = 0;
  long counter = 0;
  char *ar[MAX];
  struct timeval tv;
  long long start, end, memory, cpu;
  char buff[] = "abcdefghABCDEFG123\n";
  char *p;
  
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

  printf("generic operations ");
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  gettimeofday(&tv, NULL);
  for(i = 0; i < 10000000; i++) {
    counter++;
    p = strchr(buff, '1');
    k = atoi(p);
    counter = k * counter;
    if(i % 1000000 == 0) {
      fflush(stdout);
      printf(".");
    }
  }
  printf("\n");
  gettimeofday(&tv, NULL);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  cpu = (end - start)/1000;
  
  printf("==========================\n");
  printf("memory: %lldms\n", memory);
  printf("processing: %lldms\n", cpu);
  printf("io: n/a\n");
  printf("==========================\n");
	 
  return 0;
}
