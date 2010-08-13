/**
 * Utilities for the quality of service module mod_qos.
 *
 * Log data signing tool to ensure data integrity.
 *
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2010 Pascal Buchbinder
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

static const char revision[] = "$Id: qssign.c,v 1.1 2010-08-13 19:43:14 pbuchbinder Exp $";

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* openssl */
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* apr/apr-util */
#include <apr_base64.h>

#define MAX_LINE 65536
#define CR 13
#define LF 10
#define SEQDIG "12"
/*
 * reads a line from stdin
 */
int qs_getLine(char *s, int n) {
  int i = 0;
  while (1) {
    s[i] = (char)getchar();
    if(s[i] == EOF) return 0;
    if (s[i] == CR) {
      s[i] = getchar();
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
      s[i] = '\0';
      return 1;
    }
    ++i;
  }
}

static void qs_sign(const char *sec) {
  int sec_len = strlen(sec);
  long nr = 0;
  char line[MAX_LINE];
  int dig = atoi(SEQDIG);
  int line_size = sizeof(line) - 1 - dig; /* <data> ' ' <sequence number> */
  while(qs_getLine(line, line_size)) {
    HMAC_CTX ctx;
    unsigned char data[HMAC_MAX_MD_CBLOCK];
    unsigned int len;
    char *m;
    int data_len;
    sprintf(&line[strlen(line)], " %."SEQDIG"ld", nr);
    HMAC_Init(&ctx, sec, sec_len, EVP_sha1());
    HMAC_Update(&ctx, (const unsigned char *)line, strlen(line));
    HMAC_Final(&ctx, data, &len);
    m = calloc(1, apr_base64_encode_len(len) + 1);
    data_len = apr_base64_encode(m, (char *)data, len);
    m[data_len] = '\0';
    printf("%s#%s\n", line, m);
    free(m);
    nr++;
  }
  return;
}

int main(int argc, const char * const argv[]) {
  const char sec[] = "123";
  qs_sign(sec);
  return 0;
}
