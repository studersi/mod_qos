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
  argc--;
  argv++;
  if(argc >= 1) {
    FILE *f;
    int pagesize = getpagesize();
    char buf[1024];
    int pid = atoi(argv[0]);
    memset(buf, 0, 1024);
    sprintf(buf, "/proc/%d/statm", pid);
    f = fopen(buf, "r");
    if(f) {
      statm_t result;
      if(7 == fscanf(f,"%ld %ld %ld %ld %ld %ld %ld",
		     &result.size, &result.resident, &result.share,
		     &result.text,&result.lib,&result.data,&result.dt)) {
	printf("vsz %d\n", result.size * pagesize / 1024);
      }
      fclose(f);
    }
  } else {
    printf("usage: vsz <pid>\n");
    return 1;
  }

  return 0;
}
