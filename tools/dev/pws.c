/**
 *
 * Copyright (C) 2012 Pascal Buchbinder
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

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* apr */
#include <pcre.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>
#include <apr_base64.h>

/* OpenSSL  */
#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/safestack.h>

static const char revision[] = "$Id: pws.c,v 1.2 2012-01-16 19:51:53 pbuchbinder Exp $";

#define MAX_LINE 32768
#define QOSCR    13
#define QOSLF    10
#define DELIM    "###"
#define RAND_SIZE 10

typedef struct {
  char *d;
  char *e;
} pwd_t;

/**
 * reads a single line from f into the buffer s
 */
static int fgetLine(char *s, int n, apr_file_t *f) {
  register int i = 0;
  s[0] = '\0';
  while (1) {
    if(apr_file_getc(&s[i], f) != APR_SUCCESS) {
      s[i] = EOF;
    }
    if (s[i] == QOSCR) {
      if(apr_file_getc(&s[i], f) != APR_SUCCESS) {
        s[i] = EOF;
      }
    }
    if ((s[i] == 0x4) || (s[i] == QOSLF) || (i == (n - 1))) {
      s[i] = '\0';
      return (apr_file_eof(f) == APR_EOF ? 1 : 0);
    }
    ++i;
  }
}

static char *decrypt64(apr_pool_t *pool, unsigned char *key, const char *str) {
  EVP_CIPHER_CTX cipher_ctx;
  int len = 0;
  int buf_len = 0;
  unsigned char *buf;
  char *dec = (char *)apr_palloc(pool, 1 + apr_base64_decode_len(str));
  int dec_len = apr_base64_decode(dec, str);
  buf = apr_pcalloc(pool, dec_len);

  EVP_CIPHER_CTX_init(&cipher_ctx);
  EVP_DecryptInit(&cipher_ctx, EVP_des_ede3_cbc(), key, NULL);
  if(!EVP_DecryptUpdate(&cipher_ctx, (unsigned char *)&buf[buf_len], &len,
                        (const unsigned char *)dec, dec_len)) {
    goto failed;
  }
  buf_len+=len;
  if(!EVP_DecryptFinal(&cipher_ctx, (unsigned char *)&buf[buf_len], &len)) {
    goto failed;
  }
  buf_len+=len;
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  
  if(buf_len < RAND_SIZE) {
    goto failed;
  }
  if(buf[RAND_SIZE-1] != 'A') {
    goto failed;
  }
  buf = &buf[RAND_SIZE];
  buf_len = buf_len - RAND_SIZE;

  return apr_pstrndup(pool, (char *)buf, buf_len);
     
 failed:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  return NULL;
}

// TODO vary length
static char *encrypt64(apr_pool_t *pool, unsigned char *key, const char *str) {
  char *e;
  EVP_CIPHER_CTX cipher_ctx;
  int buf_len = 0;
  int len = 0;
  unsigned char *rand = apr_pcalloc(pool, RAND_SIZE);
  unsigned char *buf = apr_pcalloc(pool,
                                   RAND_SIZE +
                                   strlen(str) +
                                   EVP_CIPHER_block_size(EVP_des_ede3_cbc()));
  RAND_bytes(rand, RAND_SIZE);
  rand[RAND_SIZE-1] = 'A';
  EVP_CIPHER_CTX_init(&cipher_ctx);
  EVP_EncryptInit(&cipher_ctx, EVP_des_ede3_cbc(), key, NULL);
  if(!EVP_EncryptUpdate(&cipher_ctx, &buf[buf_len], &len,
                        rand, RAND_SIZE)) {
    goto failed;
  }
  buf_len+=len;
  if(!EVP_EncryptUpdate(&cipher_ctx, &buf[buf_len], &len,
                        (const unsigned char *)str, strlen(str))) {
    goto failed;
  }
  buf_len+=len;
  if(!EVP_EncryptFinal(&cipher_ctx, &buf[buf_len], &len)) {
    goto failed;
  }
  buf_len+=len;
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);

  e = (char *)apr_pcalloc(pool, 1 + apr_base64_encode_len(buf_len));
  len = apr_base64_encode(e, (const char *)buf, buf_len);
  e[len] = '\0';
  return e;

 failed:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  return NULL;
}

static char *genPwd(apr_pool_t *pool) {
  char *e;
  int len;
  unsigned char *rand = apr_pcalloc(pool, RAND_SIZE);
  RAND_bytes(rand, RAND_SIZE);
  e = (char *)apr_pcalloc(pool, 1 + apr_base64_encode_len(RAND_SIZE));
  len = apr_base64_encode(e, (const char *)rand, RAND_SIZE);
  e[12] = '\0';
  e[e[2]%10+1] = '.';
  return e;
}

static void writeDb(apr_pool_t *pool, const char *db, apr_table_t *entries) {
  apr_file_t *f = NULL;
  if(apr_file_open(&f, db, APR_WRITE|APR_CREATE|APR_TRUNCATE,
		   APR_OS_DEFAULT, pool) == APR_SUCCESS) {
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *) apr_table_elts(entries)->elts;
    for(i = 0; i < apr_table_elts(entries)->nelts; i++) {
      char *name = entry[i].key;
      pwd_t *e = (pwd_t *)entry[i].val;
      apr_file_printf(f, "%s%s%s\n", name, DELIM, e->e);
    }
    apr_file_close(f);
  } else {
    fprintf(stderr, "ERROR, failed to read database file\n");
    exit(1);
  }
}

static void setKey(apr_pool_t *pool, const char *pwd, unsigned char *key) {
  unsigned char *sec = (unsigned char *)apr_pstrcat(pool, pwd, "ksG2.asd/amindHdç5", NULL);
  int len = strlen((char *)sec);
  EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL, sec, len, 1, key, NULL);
  memset(sec, len, 0);
  len = strlen(pwd);
  memset((char *)pwd, len, 0);
}

static char *readPassword(apr_pool_t *pool, const char *prompt) {
  char buf[MAX_LINE];
  buf[0] = '\0';
  UI_UTIL_read_pw_string(buf, sizeof(buf), prompt, 0);
  return apr_pstrdup(pool, buf);
}

static apr_table_t *readDb(apr_pool_t *pool, const char *db, unsigned char *key) {
  apr_file_t *f = NULL;
  apr_table_t *entries = apr_table_make(pool, 20);
  char *pwd;
  pwd = readPassword(pool, "enter your passphrase: ");
  setKey(pool, pwd, key);
  if(apr_file_open(&f, db, APR_READ, APR_OS_DEFAULT, pool) == APR_SUCCESS) {
    char line[MAX_LINE];
    while(!fgetLine(line, sizeof(line), f)) {
      char *v = strstr(line, DELIM);
      if(v) {
	pwd_t *entry = apr_pcalloc(pool, sizeof(pwd_t));
	v[0] = '\0';
	v += strlen(DELIM);
	entry->e = apr_pstrdup(pool, v);
	entry->d = decrypt64(pool, key, v); 
	if(entry->d == NULL) {
	  fprintf(stderr, "ERROR, failed to decrypt password for id '%s'\n", line);
	}
	apr_table_setn(entries, apr_pstrdup(pool, line), (char *)entry);
      }
    }
    apr_file_close(f);
  } else {
    fprintf(stderr, "ERROR, failed to read database file\n");
    exit(1);
  }
  return entries;
}

static void usage(const char *cmd) {
  printf("\n");
  printf("Simple password store.\n");
  printf("\n");
  printf("Usage: %s -d <db file> [-c <id>] [-a <id> <password>]\n", cmd);
  printf("\n");
  exit(1);
}

int main(int argc, const char *const argv[]) {
  unsigned char key[EVP_MAX_KEY_LENGTH];
  const char *db = NULL;
  const char *id = NULL;
  const char *password = NULL;
  const char *cmd = strrchr(argv[0], '/');
  apr_pool_t *pool;
  apr_table_t *entries;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  if(cmd == NULL) {
    cmd = (char *)argv[0];
  } else {
    cmd++;
  }

  argc--;
  argv++;
  while(argc >= 1) {
    if(strcmp(*argv,"-d") == 0) {
      if (--argc >= 1) {
	db = *(++argv);
      }
    } else if(strcmp(*argv,"-a") == 0) {
      if (--argc >= 2) {
	id = *(++argv);
	password = *(++argv);
	argc--;
      }
    } else if(strcmp(*argv,"-c") == 0) {
      if (--argc >= 1) {
	id = *(++argv);
      }
    } else if(strcmp(*argv,"-h") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-?") == 0) {
      usage(cmd);
    } else if(strcmp(*argv,"-help") == 0) {
      usage(cmd);
    } else {
      usage(cmd);
    }
    argc--;
    argv++;
  }


  if(db == NULL) {
    usage(cmd);
  }

  entries = readDb(pool, db, key);

  if(id) {
    // create a new entry
    pwd_t *entry = apr_pcalloc(pool, sizeof(pwd_t));
    if(password == NULL) {
      password = genPwd(pool);
    }
    entry->d = apr_pstrdup(pool, password);
    entry->e = encrypt64(pool, key, password);
    apr_table_setn(entries, id, (char *)entry);
    writeDb(pool, db, entries);
  } else {
    // display all entries
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *) apr_table_elts(entries)->elts;
    for(i = 0; i < apr_table_elts(entries)->nelts; i++) {
      char *name = entry[i].key;
      pwd_t *e = (pwd_t *)entry[i].val;
      printf("[%s] %s\n", name, e->d ? e->d : "UNKNOWN");
    }
  }

  apr_pool_destroy(pool);
  return 0;
}
