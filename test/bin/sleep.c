#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>


static void usage() {
  printf("Usage: sleep <milliseconds>\n");
  exit(1);
}

static void check(const char *s) {
  int i = 0;
  while(s[i]) {
    if(!isdigit(s[i])) {
      printf("sleep: invalid time interval '%s'\n", s);
      usage();
    }
    i++;
  }
}

int main(int argc, const char * const argv[]) {
  int duration = 500;
  struct timespec delay;
  argc--;
  argv++;
  if(argc >= 1) {
    check(argv[0]);
    duration = atoi(argv[0]);
  } else {
    usage();
  }
  delay.tv_sec  = duration / 1000;
  delay.tv_nsec = (duration%1000) * 1000000;
  nanosleep(&delay, NULL);
  return 0;
}
