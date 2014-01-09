#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <errno.h>

typedef struct {
  unsigned long size;
  unsigned long resident;
  unsigned long share;
  unsigned long text;
  unsigned long lib;
  unsigned long data;
  unsigned long dt;
} statm_t;

int main(int argc, const char * const argv[]) {
  int pid = 0;
  FILE *f;
  int pagesize = getpagesize();
  char buf[1024];

  long pageSize = sysconf(_SC_PAGESIZE);
  long freePages = sysconf(_SC_AVPHYS_PAGES);
  int sysmem = pageSize * freePages / 1024;

  const char *cmd = strrchr(argv[0], '/');
  if(cmd == NULL) {
    cmd = argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  if(argc >= 1) {
    pid = atoi(argv[0]);
  }
  if(pid == 0) {
    printf("usage: %s <pid>\n", cmd);
    return 1;
  }
  
  memset(buf, 0, 1024);
  sprintf(buf, "/proc/%d/statm", pid);
  f = fopen(buf, "r");
  if(f) {
    statm_t result;
    if(7 == fscanf(f,"%ld %ld %ld %ld %ld %ld %ld",
		   &result.size, &result.resident, &result.share,
		   &result.text,&result.lib,&result.data,&result.dt)) {
      //printf("free %d\n", sysmem);
      printf("vsz %ld\n", result.size * pagesize / 1024);
    }
    fclose(f);
  }
  return 0;
}
