/**
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2019 Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

static const char revision[] = "$Id$";

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
#include <apr_escape.h>

#define CR 13
#define LF 10

static int m_binary = 0;

static int qs_getLine(char *s, int n, int *len) {
  int i = 0;
  *len = 0;
  while (1) {
    s[i] = (char)getchar();
    if(s[i] == EOF) {
      s[i] = '\0';
      *len = i;
      return 0;
    }
    if (s[i] == CR) {
      s[i] = getchar();
    }
    if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 2))) {
      s[i+1] = '\0';
      *len = i+1;
      return 1;
    }
    ++i;
  }
}

static void usage() {
  printf("usage: b64 -e|-d[ -b]|-he|-hd|-ue|-ud [<string>]\n");
  printf("\n");
  printf("Base64 (-e/-d) or hex (-he/-hd) or url (-ue/-ud) encoder/decoder.\n");
  printf("\n");
  printf("Use '-b' in conjunction with '-d' not suppressing non-printable data.\n");
  printf("\n");
  printf("See http://mod-qos.sourceforge.net/ for further details.\n");
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

static int qos_ishex(char x) {
  if((x >= '0') && (x <= '9')) return 1;
  if((x >= 'a') && (x <= 'f')) return 1;
  if((x >= 'A') && (x <= 'F')) return 1;
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

static void code(const char *mode, const char *line, int len) {
  apr_pool_t *pool;
  apr_pool_create(&pool, NULL);
  if(strcmp(mode, "-d") == 0) {
    char *dec = (char *)apr_pcalloc(pool, 1 + apr_base64_decode_len(line));
    int dec_len = apr_base64_decode(dec, line);
    if(dec_len > 0) {
      int i;
      dec[dec_len] = '\0';
      if(m_binary) {
	fwrite(dec, 1, dec_len, stdout);
      } else {
	for(i = 0; i < dec_len; i++) {
	  if(dec[i] < 32 && dec[i] != CR && dec[i] != LF) {
	    /* printable only */
	    dec[i] = '.';
	  }
	}
	printf("%s", dec);
      }
    }
  } else if(strcmp(mode, "-e") == 0) {
    char *enc = (char *)apr_pcalloc(pool, 1 + apr_base64_encode_len(len));
    int enc_len = apr_base64_encode(enc, (const char *)line, len);
    enc[enc_len] = '\0';
    printf("%s", enc);
  } else if(strcmp(mode, "-hd") == 0) {
    const char *p = line;
    while(p && p[0]) {
      if((p[0] == '\\' || p[0] == '0') &&
	 (p[1] == 'x' || p[1] == 'X') &&
	 qos_ishex(p[2]) &&
	 qos_ishex(p[3])) {
	p = p + 2;
	printf("%c", qos_hex2c(p));
	p = p + 2;
      } else if((p[0] == '%') &&
		qos_ishex(p[1]) &&
		qos_ishex(p[2])) {
	p = p + 1;
	printf("%c", qos_hex2c(p));
	p = p + 2;
      } else if(qos_ishex(p[0]) &&
		qos_ishex(p[1])) {
	printf("%c", qos_hex2c(p));
	p = p + 2;
      } else if(p[0] == ' ') {
	p++;
      } else {
	if(p[0] != CR && p[0] != LF) {
	  printf(".");
	}
	p++;
      }
    }
  } else if(strcmp(mode, "-he") == 0) {
    const unsigned char *p = (const unsigned char *)line;
    int i = 0;
    while(i < len) {
      printf("\\x%02x", p[i]);
      i++;
    }
  } else if(strcmp(mode, "-ud") == 0) {
    char *out = apr_punescape_url(pool, line, "", "", 1);
    if(out) {
      printf("%s", out);
    }
  } else if(strcmp(mode, "-ue") == 0) {
    char *out = apr_pescape_urlencoded(pool, line);
    if(out) {
      printf("%s", out);
    }
  } else {
    usage();
  }
  apr_pool_destroy(pool);
}

int main(int argc, const char *const argv[]) {
  const char *data = NULL;
  const char *mode = NULL;
  apr_app_initialize(&argc, &argv, NULL);

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-b") == 0) {
      m_binary = 1;
    } else if(strcmp(*argv,"-h") == 0) {
      usage();
    } else if(strcmp(*argv,"-?") == 0) {
      usage();
    } else if(strcmp(*argv,"-help") == 0) {
      usage();
    } else if(mode == NULL) {
      mode = *argv;
    } else {
      data = *argv;
    }
    argc--;
    argv++;
  }

  if(mode == NULL) {
    usage();
  }
  if(data != NULL) {
    code(mode, data, strlen(data));
    if(strcmp(mode, "-e") == 0 || strcmp(mode, "-he") == 0) {
      printf("\n");
    }
  } else {
    char line[32768];
    int len = 0;
    while(qs_getLine(line, sizeof(line), &len) || len > 0) {
      code(mode, line, len);
      if(strcmp(mode, "-e") == 0 || strcmp(mode, "-he") == 0) {
	printf("\n");
      }
      len = 0;
    }
  }
  return 0;
}
