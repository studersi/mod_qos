/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2007-2010 Pascal Buchbinder
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

static const char revision[] = "$Id: qspng.c,v 2.2 2010-02-24 19:31:13 pbuchbinder Exp $";

#include <stdio.h>
#include <strings.h>

#include <stdlib.h>
#include <unistd.h>
#include <png.h>

#include "qs_util.h"
#include "char.h"
#define HUGE_STRING_LEN 1024
#define X_SAMPLE_RATE 3
/* width */
#define X_COUNTS 60 * 24 / X_SAMPLE_RATE // 24 hours, every 3th sample
/* height */
#define Y_COUNTS 100
/* border */
#define XY_BORDER 20

typedef struct {
  const char* param;
  const char* name;
  int   r;
  int   g;
  int   b;
} qs_png_elt_t;

/* known graph types */
static const qs_png_elt_t qs_png_elts[] = {
  { "r/s", "requests per second",  20, 30, 135, },
  { "b/s", "bytes per second",     30, 45, 135 },
  { "av", "average response time", 40, 95, 185 },
  { "<1s", "requests faster than 1 second", 35, 95, 185 },
  { "1s", "requests faster or equal than 1 second", 35, 90, 185 },
  { "2s", "requests with 2 seconds response time", 30, 85, 185 },
  { "3s", "requests with 3 seconds response time", 25, 90, 185 },
  { "4s", "requests with 4 seconds response time", 25, 95, 185 },
  { "5s", "requests with 5 seconds response time", 15, 90, 185 },
  { ">5s", "requests slower than 5 seconds", 35, 90, 185 },
  { "ip", "IP addresses",          55, 60, 190 },
  { "qv", "created VIP sessions",  55, 50, 190 },
  { "qs", "session pass",          55, 75, 190 },
  { "qd", "access denied",         55, 70, 190 },
  { "qk", "conection closed",      55, 60, 190 },
  { "qt", "dynamic keep-alive",    55, 55, 190 },
  { "ql", "slow down",             55, 65, 190 },
  { "sl", "system load",           25, 60, 175 },
  { "m", "free memory", 35, 90, 185 },
  { NULL, NULL, 0, 0, 0 }
};

typedef struct qs_png_conf_st {
  char *path;
  char *param;
} qs_png_conf;


/************************************************************************
 * Functions
 ***********************************************************************/

/**
 * Read the stat_log data line by line
 *
 * @param s IN buffer to store line to
 * @param n IN buffer size
 * @param f IN file descriptor
 *
 * @return 1 on EOF, else 0
 */
static int qs_png_getline(char *s, int n, FILE *f) {
  register int i = 0;
  while (1) {
    s[i] = (char) fgetc(f);
    if (s[i] == CR) {
      s[i] = fgetc(f);
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
      s[i] = '\0';
      return (feof(f) ? 1 : 0);
    }
    ++i;
  }
}

/* png io callback (should write to buff/bio/bucket when using in apache) */
void lp_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
  FILE *f = png_get_io_ptr(png_ptr);
  fwrite(data, length, 1, f);
}

/* png io callback (not used) */
void lp_flush_data(png_structp png_ptr) {
  FILE *f = png_get_io_ptr(png_ptr);
  fprintf(stderr, "flush\n");
}

/**
 * Writes a single char to the graph
 *
 * @param x IN x position
 * @param y IN y position
 * @param row_pointers IN start pointer (0/0)
 * @param n IN char to write
 */
static void qs_png_write_char(int x, int y, png_bytep *row_pointers, char n) {
  int ix, iy;
  int *f = &s_X[0][0];
  switch(n) {
  case 'a': f = &s_a[0][0]; break;
  case 'b': f = &s_b[0][0]; break;
  case 'c': f = &s_c[0][0]; break;
  case 'd': f = &s_d[0][0]; break;
  case 'e': f = &s_e[0][0]; break;
  case 'f': f = &s_f[0][0]; break;
  case 'g': f = &s_g[0][0]; break;
  case 'h': f = &s_h[0][0]; break;
  case 'i': f = &s_i[0][0]; break;
  case 'j': f = &s_j[0][0]; break;
  case 'k': f = &s_k[0][0]; break;
  case 'l': f = &s_l[0][0]; break;
  case 'm': f = &s_m[0][0]; break;
  case 'n': f = &s_n[0][0]; break;
  case 'o': f = &s_o[0][0]; break;
  case 'p': f = &s_p[0][0]; break;
  case 'q': f = &s_q[0][0]; break;
  case 'r': f = &s_r[0][0]; break;
  case 's': f = &s_s[0][0]; break;
  case 't': f = &s_t[0][0]; break;
  case 'u': f = &s_u[0][0]; break;
  case 'v': f = &s_v[0][0]; break;
  case 'w': f = &s_w[0][0]; break;
  case 'x': f = &s_x[0][0]; break;
  case 'y': f = &s_y[0][0]; break;
  case 'z': f = &s_z[0][0]; break;
  case ' ': f = &s_SP[0][0]; break;
  case '_': f = &s_US[0][0]; break;
  case '(': f = &s_BRO[0][0]; break;
  case ')': f = &s_BRC[0][0]; break;
  case '<': f = &s_LT[0][0]; break;
  case '>': f = &s_GT[0][0]; break;
  case '-': f = &s_MI[0][0]; break;
  case '/': f = &s_SL[0][0]; break;
  case ';': f = &s_SC[0][0]; break;
  case ',': f = &s_CM[0][0]; break;
  case ':': f = &s_CO[0][0]; break;
  case '.': f = &s_DT[0][0]; break;
  case '\'': f = &s_SQ[0][0]; break;
  case 'A': f = &s_a[0][0]; break;
  case 'B': f = &s_b[0][0]; break;
  case 'C': f = &s_c[0][0]; break;
  case 'D': f = &s_d[0][0]; break;
  case 'E': f = &s_e[0][0]; break;
  case 'F': f = &s_f[0][0]; break;
  case 'G': f = &s_g[0][0]; break;
  case 'H': f = &s_h[0][0]; break;
  case 'I': f = &s_i[0][0]; break;
  case 'J': f = &s_j[0][0]; break;
  case 'K': f = &s_k[0][0]; break;
  case 'L': f = &s_l[0][0]; break;
  case 'M': f = &s_M[0][0]; break;
  case 'N': f = &s_n[0][0]; break;
  case 'O': f = &s_o[0][0]; break;
  case 'P': f = &s_p[0][0]; break;
  case 'Q': f = &s_q[0][0]; break;
  case 'R': f = &s_r[0][0]; break;
  case 'S': f = &s_s[0][0]; break;
  case 'T': f = &s_t[0][0]; break;
  case 'U': f = &s_u[0][0]; break;
  case 'V': f = &s_v[0][0]; break;
  case 'W': f = &s_w[0][0]; break;
  case 'X': f = &s_x[0][0]; break;
  case 'Y': f = &s_y[0][0]; break;
  case 'Z': f = &s_z[0][0]; break;
  case '0': f = &s_0[0][0]; break;
  case '1': f = &s_1[0][0]; break;
  case '2': f = &s_2[0][0]; break;
  case '3': f = &s_3[0][0]; break;
  case '4': f = &s_4[0][0]; break;
  case '5': f = &s_5[0][0]; break;
  case '6': f = &s_6[0][0]; break;
  case '7': f = &s_7[0][0]; break;
  case '8': f = &s_8[0][0]; break;
  case '9': f = &s_9[0][0]; break;
  }
  /* print the char matrix */
  for(iy = 0; iy < S_H_MAX; iy++) {
    png_byte* row = row_pointers[y+iy];
    for(ix = 0; ix < S_W_MAX; ix++) {
      png_byte* ptr = &(row[(x+ix)*4]);
      if(f[iy*S_W_MAX + ix] == 1) {
        /* foreground */
	ptr[0] = 0;
	ptr[1] = 0;
	ptr[2] = 0;
      } else {
        /* background */
	ptr[0] = 250;
	ptr[1] = 250;
	ptr[2] = 255;
      }
    }
  }
}

/**
 * Writes a single digit 0..9.
 * You should normally use either qs_png_write_int() or qs_png_write_int().
 *
 * @param x IN x position
 * @param y IN y position
 * @param row_pointers IN start pointer (0/0)
 * @param n IN number to write
 */
static void qs_png_write_digit(int x, int y, png_bytep *row_pointers, int n) {
  char f = 'X';
  if(n == 0) f = '0';
  if(n == 1) f = '1';
  if(n == 2) f = '2';
  if(n == 3) f = '3';
  if(n == 4) f = '4';
  if(n == 5) f = '5';
  if(n == 6) f = '6';
  if(n == 7) f = '7';
  if(n == 8) f = '8';
  if(n == 9) f = '9';
  qs_png_write_char(x, y, row_pointers, f);
}

/**
 * Writes a string to the graph.
 *
 * @param x IN x position
 * @param y IN y position
 * @param row_pointers IN start pointer (0/0)
 * @param n IN string to write
 */
static void qs_png_write_string(int x, int y, png_bytep *row_pointers, const char *n) {
  int i = 0;
  int offset = 0;
  while(n[i] != '\0') {
    qs_png_write_char(x+offset, y, row_pointers, n[i]);
    i++;
    offset = offset + S_W_MAX;
  }
}

/**
 * Writes a number (int) to the graph (1:1).
 *
 * @param x IN x position
 * @param y IN y position
 * @param row_pointers IN start pointer (0/0)
 * @param n IN number to write
 */
static void qs_png_write_int(int x, int y, png_bytep *row_pointers, int n) {
  char num_str[HUGE_STRING_LEN];
  snprintf(num_str, sizeof(num_str), "%d", n);
  qs_png_write_string(x, y, row_pointers, num_str);
}

/**
 * Writes a number (long) to the graph using k,M for big numbers.
 *
 * @param x IN x position
 * @param y IN y position
 * @param row_pointers IN start pointer (0/0)
 * @param n IN string to write
 */
static void qs_png_write_long(int x, int y, png_bytep *row_pointers, long n) {
  char num_str[HUGE_STRING_LEN];
  snprintf(num_str, sizeof(num_str), "%ld", n);
  if(n >= 1000) {
    snprintf(num_str, sizeof(num_str), "%ldk", n/1000);
  }
  if(n >= 1000000) {
    snprintf(num_str, sizeof(num_str), "%ldM", n/1000000);
  }
  qs_png_write_string(x, y, row_pointers, num_str);
}

/**
 * Labels the graph (min,max,title).
 *
 * @param width IN size (x axis) of the graph
 * @param height IN size (y axis) of the graph
 * @param border IN border size around the graph
 * @param row_pointers IN start pointer (0/0)
 * @param max IN max y value
 * @param name IN title
 */
static void qs_png_label(int width, int height, int border,
                           png_bytep *row_pointers, long max,
                           const char *name) {
  /* MAX */
  int i;
  int step = height/5;
  int c = 5;
  for(i = 0; i < height; i = i + step) {
    qs_png_write_long(1, border - (S_W_MAX/2) + i, row_pointers, max/5*c);
    c--;
  }

  /* MIN */
  qs_png_write_int(1, height + border - (S_W_MAX/2), row_pointers, 0);

  /* title */
  {
    char buf[HUGE_STRING_LEN];
    snprintf(buf, sizeof(buf), "%s", name);
    qs_png_write_string(XY_BORDER, XY_BORDER/2-S_H_MAX/2, row_pointers, buf);
  }
                        
}

lp_init(int width, int height, int border, png_bytep **start) {
  png_bytep *row_pointers;
  int b_width = width + (2 * border);
  int b_height = height + (2 * border);
  int x, y;
  
  /* alloc memory */
  row_pointers = (png_bytep*) malloc(sizeof(png_bytep) * b_height);
  for(y=0; y<b_height; y++) {
    row_pointers[y] = (png_byte*) malloc(b_width * 4);
  }
  
  /* background */
  for(y=0; y<b_height; y++) {
    png_byte* row = row_pointers[y];
    for(x=0; x<b_width; x++) {
      png_byte* ptr = &(row[x*4]);
      ptr[0] = 250;
      ptr[1] = 250;
      ptr[2] = 255;
      ptr[3] = 250;
    }
  }
  for(y=border; y<b_height-border; y++) {
    png_byte* row = row_pointers[y];
    for(x=border; x<b_width-border; x++) {
      png_byte* ptr = &(row[x*4]);
      ptr[0] = 245;
      ptr[1] = 245;
      ptr[2] = 250;
    }
  }
  *start = row_pointers;
}

/**
 * "Main" png function:
 * - reads the data from the file
 * - draws the curve
 * - lables the x axis
 *
 * @param width IN size (x axis) of the graph
 * @param height IN size (y axis) of the graph
 * @param border IN border size around the graph
 * @param row_pointers IN start pointer (0/0)
 * @param stat_log IN file descriptor to the input file
 * @param name IN title
 * @param c_r IN color red (0..255)
 * @param c_g IN color green (0..255)
 * @param c_b IN color blue (0..255)
 */
static long qs_png_draw(int width, int height, int border,
                          png_bytep *row_pointers, FILE *stat_log, const char *name,
                          int c_r, int c_g, int c_b) {
  int x, y;
  long req[width];         // values
  long max_req[width];     // values
  int hours[width];        // time marks on x axis
  long tmp[X_SAMPLE_RATE]; // used to build average over multiple samples
  int sample = 1;          // sample rate counter (1 to X_SAMPLE_RATE) 

  int i = 0;
  char line[HUGE_STRING_LEN];

  long peak = 0;           // max of all values
  double scale = 1;        // scaling factor (heigth x scale = unit)

  int hour = -1;           // detect "new" hour
  char date_str[32] = "";  // sting storing the first day (if fist value is at 00h)

  long ret;
  for(x=0; x<width; x++) hours[x] = 0;
  /* reads the file and resample measure points to witdh of the graph */
  while(!qs_png_getline(line, sizeof(line), stat_log) && i < width) {
    char *p = strstr(line, name);
    req[i] = 0;
    max_req[i] = 0;
    if(p && ((p - line) > 8)) {
      char *e;
      p=p+strlen(name);
      e = strchr(p,';');
      if(e) e[0] = '\0';
      e = strchr(p, '.'); /** sl uses fp value */
      if(e) e[0] = '\0';
      tmp[sample-1] = atol(p);
    } else {
      tmp[sample-1] = 0;
    }
    /* hour (stat_log time format: %d.%m.%Y %H:%M:%S (19 char)) */
    p = strchr(line, ';');
    if(p && (p-line == 19 )) {
      p = p - 6;
      p[0] = '\0';
      p = p - 2;
      hours[i] = atoi(p);
    }
    /* use the defined sample rate */
    if(sample == X_SAMPLE_RATE) {
      int j;
      int max_value = 0;
      for(j = 0; j < X_SAMPLE_RATE; j++) {
	req[i] = req[i] + tmp[j];
        if(max_value < tmp[j]) {
          max_value = tmp[j];
        }
      }
      max_req[i] = max_value;
      if(max_req[i] > peak) peak = max_req[i];
      /* build average */
      req[i] = req[i] / X_SAMPLE_RATE;
      sample = 1;
      i++;
      /* and store the current date (%d.%m.%Y (10 char)) if the
         first value is at 00h */
      if(hours[i] == 0 && i == 1) {
        p = strchr(line, ' ');
        if(p && (p-line == 10)) {
          p[0] = '\0';
          strcpy(date_str, line);
        }
      }
    } else {
      sample++;
    }
  }
  /* calculate y axis scaling (1:1 are heigth pixels) */
  if(peak < 10) {
    scale = 0.1;
  } else {
    while((peak / scale) > height) {
      if(scale < 8) {
        scale = scale * 2;
      } else {
        if(scale == 8) {
          scale = 10;
        } else {
          scale = scale * 10;
        }
      }
    }
  }

  /* draw the curve */
  for(x=0; x<i; x++) {
    /* max */
    for(y=0; y<(max_req[x]/scale); y++) {
      png_byte* row = row_pointers[height-y-1+border];
      png_byte* ptr = &(row[x*4+(4*border)]);
      ptr[0] = c_r + 50;
      ptr[1] = c_g + 50;
      ptr[2] = c_b + 50;
    }
    /* average */
    for(y=0; y<(req[x]/scale); y++) {
      png_byte* row = row_pointers[height-y-1+border];
      png_byte* ptr = &(row[x*4+(4*border)]);
      ptr[0] = c_r;
      ptr[1] = c_g;
      ptr[2] = c_b;
    }
    /* label the x axis */
    if(hour != hours[x]) {
      hour = hours[x];
      for(y=0; y<(height); y=y+3) {
	png_byte* row = row_pointers[y+border];
	png_byte* ptr = &(row[x*4+(4*border)]);
	ptr[0] = 50;
	ptr[1] = 50;
	ptr[2] = 50;
      }
      if(hour%2 == 0) {
        qs_png_write_digit(x-S_W_MAX+border, height + border + 1, row_pointers, hour/10);
	qs_png_write_digit(x-S_W_MAX+border+S_W_MAX, height + border + 1, row_pointers, hour%10);
	qs_png_write_char(x-S_W_MAX+border+2*S_W_MAX, height + border + 1, row_pointers, 'h');
      }
    }
  }

  /* print date */
  qs_png_write_string(border, height+border+2+S_H_MAX, row_pointers, date_str);

  /* horizontal lines every 1/4 height */
  for(y=(height/5); y<height; y=y+height/5) {
    png_byte* row = row_pointers[y+border];
    for(x=0; x<i; x=x+3) {
      png_byte* ptr = &(row[x*4+(4*border)]);
      ptr[0] = 50;
      ptr[1] = 50;
      ptr[2] = 50;
    }
  }

  ret = scale * height;
  return ret;
}


static void usage(char *cmd) {
  printf("\n");
  printf("Utility to draw a png graph from qslog output data.\n");
  printf("\n");
  printf("Usage: %s -i <stat_log_file> -p <parameter> -o <out_file> [-10]\n", cmd);
  printf("\n");
  printf("Summary\n");
  printf("%s is a tool to generate png (portable network graphics)\n", cmd);
  printf("raster images files from semicolon separated data generated by the\n");
  printf("qslog utility. It reads up to the first 1440 entries (24 hours)\n");
  printf("and prints a graph using the values defined by the 'parameter' \n");
  printf("name.\n");
  printf("\n");
  printf("Options\n");
  printf("  -i <stats_log_file>\n");
  printf("     Input file to read data from.\n");
  printf("  -p <parameter>\n");
  printf("     Parameter name, e.g. r/s or usr.\n");
  printf("  -o <out_file>\n");
  printf("     Output file name, e.g. stat.png.\n");
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
  exit(1);
}

int main(int argc, char **argv) {
  int x, y;
  int width, height, b_width, b_height;
  png_byte color_type;
  png_byte bit_depth;

  int scale;

  char nameBuffer[1024];
  png_structp png_ptr;
  png_infop info_ptr;

  png_bytep *row_pointers;

  char *infile = NULL;
  FILE *f;
  FILE *stat_log;

  char *cmd = strrchr(argv[0], '/');
  const char *param = NULL;
  const char *name = "";
  char *out = NULL;
  int c_r = 20;
  int c_g = 175;
  int c_b = 50;
  const qs_png_elt_t* elt;
  int i, j;

  if(cmd == NULL) {
    cmd = argv[0];
  } else {
    cmd++;
  }

  while(argc >= 1) {
    if(strcmp(*argv,"-i") == 0) {
      if (--argc >= 1) {
	infile = *(++argv);
      } 
    } else if(strcmp(*argv,"-p") == 0) {
      if (--argc >= 1) {
	param = *(++argv);
	name = param;
      }
    } else if(strcmp(*argv,"-o") == 0) {
      if (--argc >= 1) {
	out = *(++argv);
      }
    }
    argc--;
    argv++;
  }
  
  
  if(infile == NULL || param == NULL || out == NULL) usage(cmd);
  for(elt = qs_png_elts; elt->param != NULL ; ++elt) {
    if(strcmp(elt->param, param) == 0) {
      name = elt->name;
      c_r = elt->r;
      c_g = elt->g;
      c_b = elt->b;
    }
  }

  stat_log = fopen(infile, "r"); 
  if(stat_log == NULL) {
    fprintf(stderr,"[%s]: ERROR, could not open input file <%s>\n", cmd, infile);
    exit(1);
  }

  f = fopen(out, "wb"); 
  if(f == NULL) {
    fprintf(stderr,"[%s]: ERROR, could not open output file <%s>\n", cmd, out);
    exit(1);
  }

  png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if(png_ptr == NULL) {
    fprintf(stderr,"[%s]: ERROR, could not create png struct\n", cmd);
    exit(1);
  }
  info_ptr = png_create_info_struct(png_ptr);
  if(info_ptr == NULL) {
    fprintf(stderr,"[%s]: ERROR, could not create png infromation struct\n", cmd);
    exit(1);
  }
  if(setjmp(png_jmpbuf(png_ptr))) {
    fprintf(stderr,"[%s]: ERROR, could not init png struct\n", cmd);
    exit(1);
  }
  png_set_write_fn(png_ptr, f, lp_write_data, NULL);

  /* write header */
  if(setjmp(png_jmpbuf(png_ptr))) {
    fprintf(stderr,"[%s]: ERROR, could not write png header\n", cmd);
    exit(1);
  }

  color_type = PNG_COLOR_TYPE_RGB_ALPHA;
  bit_depth = 8;
  width = X_COUNTS;
  height = Y_COUNTS;
  b_width = width + (2 * XY_BORDER);
  b_height = height + (2 * XY_BORDER);

  png_set_IHDR(png_ptr, info_ptr,
	       b_width, b_height,
	       bit_depth,
	       color_type,
	       PNG_INTERLACE_NONE,
	       PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
  png_write_info(png_ptr, info_ptr);

  /* write bytes */
  if(setjmp(png_jmpbuf(png_ptr))) {
    fprintf(stderr,"[%s]: ERROR, could not write png data\n", cmd);
    exit(1);
  }

  /* alloc and background */
  lp_init(width, height, XY_BORDER, &row_pointers);

  /* paint */
  {
    char buf[HUGE_STRING_LEN];
    snprintf(buf, sizeof(buf), ";%s;", param);
    scale = qs_png_draw(width, height, XY_BORDER, row_pointers,
			stat_log, buf, c_r, c_g, c_b);
  }

  /* min/max/title label */
  qs_png_label(width, height, XY_BORDER, row_pointers, scale,
	       name);


  /* done, write image */
  png_write_image(png_ptr, row_pointers);
  /* end write */
  if(setjmp(png_jmpbuf(png_ptr))) {
    fprintf(stderr,"[%s]: ERROR, could not write png data\n", cmd);
    exit(1);
  }
  png_write_end(png_ptr, NULL);

  /* cleanup heap allocation */
  for(y=0; y<height; y++) {
    free(row_pointers[y]);
  }
  free(row_pointers);

  fclose(f);
  fclose(stat_log);
  return 0;
}
