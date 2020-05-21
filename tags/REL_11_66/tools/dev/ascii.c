
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main(int argc, const char * const argv[]) {
  int i;
  for(i = 32; i < 127; i++) {
    printf("%3.d %x %c\n", i, i, i);
  }

  return 0;
}
