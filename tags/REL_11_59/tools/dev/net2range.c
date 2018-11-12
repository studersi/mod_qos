/**
 * Converts an IP network (CIDR notation) into its
 * address range by the networks starting and ending
 * IP address represented as an integer.
 *
 * Tool is used to covert MaxMind GeoLite2Country
 * files to GeoLiteCountry (legacy) format files.
 *
 * see maxMindConvert.sh
 */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

typedef struct {
  int w;
  int x;
  int y;
  int z;
} qs_mask_t;

static const qs_mask_t qs_mask[] = {
  { 255, 255, 255, 255 },
  { 255, 255, 255, 254 },
  { 255, 255, 255, 252 },
  { 255, 255, 255, 248 },
  { 255, 255, 255, 240 },
  { 255, 255, 255, 224 },
  { 255, 255, 255, 192 },
  { 255, 255, 255, 128 },
  { 255, 255, 255, 0 },
  { 255, 255, 254, 0 },
  { 255, 255, 252, 0 },
  { 255, 255, 248, 0 },
  { 255, 255, 240, 0 },
  { 255, 255, 224, 0 },
  { 255, 255, 192, 0 },
  { 255, 255, 128, 0 },
  { 255, 255, 0, 0 },
  { 255, 254, 0, 0 },
  { 255, 252, 0, 0 },
  { 255, 248, 0, 0 },
  { 255, 240, 0, 0 },
  { 255, 224, 0, 0 },
  { 255, 192, 0, 0 },
  { 255, 128, 0, 0 },
  { 255, 0, 0, 0 },
  { 254, 0, 0, 0 },
  { 252, 0, 0, 0 },
  { 248, 0, 0, 0 },
  { 240, 0, 0, 0 },
  { 224, 0, 0, 0 },
  { 192, 0, 0, 0 },
  { 128, 0, 0, 0 },
  { 0, 0, 0, 0 }
};

static void usage() {
  printf("usage: net2range <network>\n");
  printf("\n");
  exit(1);
}

int main(int argc, const char * const argv[]) {
  char *a, *p;
  int w,x,y,z,n;
  qs_mask_t m;

  argc--;
  argv++;
  if(argc != 1) {
    usage();
  }
  a = *argv;
  p = strchr(a, '.');
  if(p == NULL) usage();
  p[0] = '\0';
  w = atoi(a);
  if(w < 0 || w > 255) usage();
  
  a = &p[1];
  p = strchr(a, '.');
  if(p == NULL) usage();
  p[0] = '\0';
  x = atoi(a);
  if(x < 0 || x > 255) usage();

  a = &p[1];
  p = strchr(a, '.');
  if(p == NULL) usage();
  p[0] = '\0';
  y = atoi(a);
  if(y < 0 || y > 255) usage();

  a = &p[1];
  p = strchr(a, '/');
  if(p == NULL) usage();
  p[0] = '\0';
  z = atoi(a);
  if(z < 0 || z > 255) usage();

  p++;
  n = atoi(p);
  if(n < 0 || n > 32) usage();

  m = qs_mask[32-n];

  printf("\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%.10u\",\"%.10u\"\n",
	 w & m.w, x & m.x, y & m.y, z & m.z,
	 (w & m.w) + (255-m.w), (x & m.x) + (255-m.x), (y & m.y) + (255-m.y), (z & m.z) + (255-m.z),
	 (w & m.w)*16777216 + (x & m.x)*65536 + (y & m.y)*256 + (z & m.z),
	 ((w & m.w) + (255-m.w))*16777216 + ((x & m.x) + (255-m.x))*65536 + ((y & m.y) + (255-m.y))*256 + ((z & m.z) + (255-m.z)));

  return 0;
}
