/**
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2007-2009 Pascal Buchbinder
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

static const char revision[] = "$Id: b64.c,v 1.1 2009-01-19 20:30:06 pbuchbinder Exp $";

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* apr */
#include <apr_base64.h>
#include <apr_strings.h>

static void usage() {
  printf("usage: b64 -e|-d <string>\n");
  exit(1);
}

int main(int argc, char **argv) {
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
      dec[dec_len] = '\0';
      printf("%s\n", dec);
    }
  } else if(strcmp(argv[0], "-e") == 0) {
    char *enc = (char *)apr_pcalloc(pool, 1 + apr_base64_encode_len(strlen(argv[1])));
    int enc_len = apr_base64_encode(enc, (const char *)argv[1], strlen(argv[1]));
    enc[enc_len] = '\0';
    printf("%s\n", enc);
  }
  apr_pool_destroy(pool);
  return 0;
}
