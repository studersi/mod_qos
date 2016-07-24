/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <sys/time.h>

/* OpenSSL  */
#include <openssl/rand.h>

/* APR */
#include <pcre.h>
#include <apr.h>
#include <apr_uri.h>
#include <apr_signal.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_support.h>

#define RAND_SIZE 10

static void qrnd(int max) {
  int i;
  long long start;
  long long end;
  struct timeval tv;
  unsigned char buf[RAND_SIZE];

  gettimeofday(&tv, NULL);
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  for(i = 0; i < max; i++) {
    if(RAND_bytes(buf, RAND_SIZE) == 0) {
      fprintf(stderr, "no random data available!");
      exit(1);
    }
  }
  gettimeofday(&tv, NULL);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  printf("RAND_bytes: %dx %lld usec\n", max, (end - start) / max);
}

static void qaprnd(int max) {
  int i;
  long long start;
  long long end;
  struct timeval tv;
  unsigned char buf[RAND_SIZE];

  gettimeofday(&tv, NULL);
  start = tv.tv_sec * 1000000 + tv.tv_usec;
  for(i = 0; i < max; i++) {
    if(apr_generate_random_bytes(buf, RAND_SIZE) != APR_SUCCESS) {
      fprintf(stderr, "no random data available!");
      exit(1);
    }
  }
  gettimeofday(&tv, NULL);
  end = tv.tv_sec * 1000000 + tv.tv_usec;
  printf("apr_generate_random_bytes: %dx %lld usec\n", max, (end - start) / max);
}

int main(int argc, const char *const argv[]) {
  apr_app_initialize(&argc, &argv, NULL);
  qrnd(100);
  qrnd(1000);
  qrnd(10000);
  qrnd(100000);

  qaprnd(100);
  qaprnd(1000);
  qaprnd(10000);
  qaprnd(100000);

  return 0;
}
