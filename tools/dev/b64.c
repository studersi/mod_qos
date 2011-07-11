/**
 * See http://opensource.adnovum.ch/mod_qos/ for further
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

static const char revision[] = "$Id: b64.c,v 1.7 2011-07-11 20:53:19 pbuchbinder Exp $";

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

/* apr */
#include <apr_base64.h>
#include <apr_strings.h>

static void usage() {
  printf("usage: b64 -e|-d|-he|-hd <string>\n");
  printf("\n");
  printf("Base64 (or hex) encoder/decoder.\n");
  printf("\n");
  printf("See http://opensource.adnovum.ch/mod_qos/ for further details.\n");
  exit(1);
}

static int qos_is_utf8(unsigned char *in) {
  // byte 0: 110x xxxx (0xc0) byte 1: 10xx xxxx (0x80)
  if(((in[0] & 0xe0) == 0xc0) &&
     ((in[1] & 0xc0) == 0x80)) {
    return 2;
  }
  // byte 0: 1110 xxxx (0xe0)
  if(((in[0] & 0xf0) == 0xe0) &&
     ((in[1] & 0xc0) == 0x80) &&
     ((in[2] & 0xc0) == 0x80)) {
    return 3;
  }
  // byte 0: 1111 0xxx (0xf0)
  if(((in[0] & 0xf8) == 0xf0) &&
     ((in[1] & 0xc0) == 0x80) &&
     ((in[2] & 0xc0) == 0x80) &&
     ((in[3] & 0xc0) == 0x80)) {
    return 4;
  }
  // byte 0: 1111 10xx (0xf8)
  if(((in[0] & 0xfc) == 0xf8) &&
     ((in[1] & 0xc0) == 0x80) &&
     ((in[2] & 0xc0) == 0x80) &&
     ((in[3] & 0xc0) == 0x80) &&
     ((in[4] & 0xc0) == 0x80)) {
    return 5;
  }
  // byte 0: 1111 110x (0xfc)
  if(((in[0] & 0xfe) == 0xfc) &&
     ((in[1] & 0xc0) == 0x80) &&
     ((in[2] & 0xc0) == 0x80) &&
     ((in[3] & 0xc0) == 0x80) &&
     ((in[4] & 0xc0) == 0x80) &&
     ((in[5] & 0xc0) == 0x80)) {
    return 6;
  }
  // single byte char
  return 0;
}

static int qos_hex2c(const char *x) {
  int i, ch;
  ch = x[0];
  if (isdigit(ch)) {
    i = ch - '0';
  }else if (isupper(ch)) {
    i = ch - ('A' - 10);
  } else {
    i = ch - ('a' - 10);
  }
  i <<= 4;
  
  ch = x[1];
  if (isdigit(ch)) {
    i += ch - '0';
  } else if (isupper(ch)) {
    i += ch - ('A' - 10);
  } else {
    i += ch - ('a' - 10);
  }
  return i;
}

int main(int argc, const char *const argv[]) {
  apr_pool_t *pool;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  argc--;
  argv++;
  if(argc != 2) {
    usage();
  }
  if(strcmp(argv[0], "-d") == 0) {
    char *dec = (char *)apr_palloc(pool, 1 + apr_base64_decode_len(argv[1]));
    int dec_len = apr_base64_decode(dec, argv[1]);
    if(dec_len > 0) {
      int i;
      dec[dec_len] = '\0';
      for(i = 0; i < dec_len; i++) {
	if(dec[i] < 32) {
	  /* printable only */
	  dec[i] = '.';
	}
      }
      printf("%s\n", dec);
    }
  } else if(strcmp(argv[0], "-e") == 0) {
    char *enc = (char *)apr_pcalloc(pool, 1 + apr_base64_encode_len(strlen(argv[1])));
    int enc_len = apr_base64_encode(enc, (const char *)argv[1], strlen(argv[1]));
    enc[enc_len] = '\0';
    printf("%s\n", enc);
  } else if(strcmp(argv[0], "-hd") == 0) {
    const char *p = argv[1];
    while(p && p[0]) {
      if(p[0] == '\\' && (p[1] == 'x' || p[1] == 'X')) {
	p = p + 2;
	if(strlen(p) < 2) {
	  p = NULL;
	} else {
	  printf("%c", qos_hex2c(p));
	  p = p + 2;
	}
      } else {
	p++;
      }
    }
    printf("\n");
  } else if(strcmp(argv[0], "-he") == 0) {
    const unsigned char *p = (const unsigned char *)argv[1];
    while(p && p[0]) {
      printf("\\x%02x", p[0]);
      p++;
    }
    printf("\n");
  }
  apr_pool_destroy(pool);
  return 0;
}
