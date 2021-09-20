/**
 *
 * pws.c: (very) simple password vault.
 * 
 * Copyright (C) 2021 Pascal Buchbinder
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

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

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

static const char revision[] = "$Id$";

#define MAX_LINE 32768
#define QOSCR    13
#define QOSLF    10
#define DELIM    "###"
#define RAND_SIZE 10
#define CHECKA   "pws-dummyaccount"

typedef struct {
  char *name;    // account/login id
  char *pwd;     // encrypted password
  char *comment; // comment about the account
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

/**
 * Decrypts the b64 encoded data, see encrypt64()
 */
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

/**
 * Encryptes and b64 encodes the provided string, see decrypt64()
 */
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

/**
 * creates a new passphrase (proposal, user can modify it)
 */
static char *genPwd(apr_pool_t *pool) {
  char *p;
  char *e;
  unsigned char *rand = apr_pcalloc(pool, RAND_SIZE);
  RAND_bytes(rand, RAND_SIZE);
  e = (char *)apr_pcalloc(pool, 1 + apr_base64_encode_len(RAND_SIZE));
  apr_base64_encode(e, (const char *)rand, RAND_SIZE);
  e[12] = '\0';
  e[e[2]%10+1] = '.'; // ensure we have at least one special char
  p = e;
  // replace chars which we don't like
  while(p && p[0]) {
    if(p[0] == 'I') {
      p[0] = 'i';
    }
    if(p[0] == 'l') {
      p[0] = 'L';
    }
    if(p[0] == '1') {
      p[0] = 'k';
    }
    if(p[0] == '+') {
      p[0] = '5';
    }
    if(p[0] == '/') {
      p[0] = 'B';
    }
    p++;
  }
  return e;
}

/**
 * Sets the master passphrase for the db
 */
static void setKey(apr_pool_t *pool, const char *pwd, unsigned char *key) {
  unsigned char *sec = (unsigned char *)apr_pstrcat(pool, pwd, "ksG2.asd/amindHdç5", NULL);
  int len = strlen((char *)sec);
  EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL, sec, len, 1, key, NULL);
  memset(sec, len, 0);
  len = strlen(pwd);
  memset((char *)pwd, len, 0);
}

/**
 * Gets passphrase from stdin (no echo)
 */
static char *readPassword(apr_pool_t *pool, const char *prompt) {
  char buf[MAX_LINE];
  buf[0] = '\0';
  UI_UTIL_read_pw_string(buf, sizeof(buf), prompt, 0);
  return apr_pstrdup(pool, buf);
}

/**
 * We add a dummy entry to ensure db integrity
 */
static void addCheckEntry(apr_pool_t *pool, apr_table_t *entries, unsigned char *key) {
  pwd_t *e = (pwd_t *)apr_table_get(entries, CHECKA);
  if(e == NULL) {
    e = apr_pcalloc(pool, sizeof(pwd_t));
    e->name = apr_pstrdup(pool, CHECKA);
    e->pwd = apr_pstrdup(pool, CHECKA);
    e->comment = apr_pstrdup(pool, CHECKA);
    apr_table_setn(entries, apr_pstrdup(pool, CHECKA), (char *)e);
  }
}

/**
 * Writes all entries to the db file
 */
static void writeDb(apr_pool_t *pool, const char *db, unsigned char *key,
		    apr_table_t *entries) {
  apr_file_t *f = NULL;
  char *bak = apr_pstrcat(pool, db, ".bak", NULL);
  rename(db, bak);
  if(apr_file_open(&f, db, APR_WRITE|APR_CREATE|APR_TRUNCATE,
		   APR_OS_DEFAULT, pool) == APR_SUCCESS) {
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *) apr_table_elts(entries)->elts;
    addCheckEntry(pool, entries, key);
    for(i = 0; i < apr_table_elts(entries)->nelts; i++) {
      pwd_t *e = (pwd_t *)entry[i].val;
      apr_file_printf(f, "%s"DELIM"%s"DELIM"%s\n",
		      encrypt64(pool, key, e->name),
		      encrypt64(pool, key, e->pwd), 
		      encrypt64(pool, key, e->comment));
    }
    apr_file_close(f);
    chmod(db, S_IRUSR|S_IWUSR);
  } else {
    fprintf(stderr, "ERROR, failed to write database file\n");
  }
}

/**
 * Reads all entries from the db file
 */
static apr_table_t *readDb(apr_pool_t *pool, const char *db,
			   unsigned char *key, int action) {
  apr_file_t *f = NULL;
  apr_table_t *entries = apr_table_make(pool, 2000);
  char *pwd;
  pwd = readPassword(pool, "enter your passphrase: ");
  setKey(pool, pwd, key);
  if(apr_file_open(&f, db, APR_READ, APR_OS_DEFAULT, pool) == APR_SUCCESS) {
    char line[MAX_LINE];
    int hasCHECKA = 0;
    int lines = 0;
    while(!fgetLine(line, sizeof(line), f)) {
      lines++;
      char *v = strstr(line, DELIM);
      char *c;
      if(v) {
	pwd_t *entry = apr_pcalloc(pool, sizeof(pwd_t));
	v[0] = '\0';
	v += strlen(DELIM);
	c = strstr(v, DELIM);
	if(c) {
	  c[0] = '\0';
	  c += strlen(DELIM);
	  entry->comment = decrypt64(pool, key, c);
	} else {
	  entry->comment = apr_pstrdup(pool, "");
	}
	entry->pwd = decrypt64(pool, key, v); 
	entry->name = decrypt64(pool, key, line);
	if(entry->pwd && entry->name && entry->comment) {
	  if(strcmp(entry->pwd, CHECKA) == 0) {
	    hasCHECKA = 1;
	  } else {
	    apr_table_addn(entries, apr_psprintf(pool, "%03d", lines), (char *)entry);
	  }
	}
      }
    }
    apr_file_close(f);
    if(lines && !hasCHECKA) {
      // invalid passphrase!
      fprintf(stderr, "ERROR, invalid passphrase\n");
      exit(1);
    }
  } else {
    if(action) {
      fprintf(stderr, "failed to open the database file - create new file\n");
    } else {
      // readonly
      fprintf(stderr, "failed to open the database file (file does not exist"
	      " or is not readable)\n");
    }
  }
  return entries;
}

/**
 * Prints all entries to stdout
 */
static void printEntries(apr_pool_t *pool, apr_table_t *entries) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *) apr_table_elts(entries)->elts;
  for(i = 0; i < apr_table_elts(entries)->nelts; i++) {
    pwd_t *e = (pwd_t *)entry[i].val;
    if(strcmp(e->pwd, CHECKA) != 0) {
      printf("%s: [%s] %s (%s)\n", 
	     entry[i].key,
	     e->name,
	     e->pwd ? e->pwd : "UNKNOWN",
	     e->comment ? e->comment : "");
    }
  }
}

static void usage(const char *cmd) {
  printf("\n");
  printf("Simple password store.\n");
  printf("\n");
  printf("Usage: %s -d <db file> [-a]|[-r]|[-m]\n", cmd);
  printf("\n");
  printf(" Options:\n");
  printf(" -a Adds a new entry.\n");
  printf(" -r Removes an entry.\n");
  printf(" -m Changes the db's passphrase.\n");
  printf("\n");
  exit(1);
}

int main(int argc, const char *const argv[]) {
  int action = 0;
  unsigned char key[EVP_MAX_KEY_LENGTH];
  const char *db = NULL;
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
    if(strcmp(*argv, "-d") == 0) {
      if (--argc >= 1) {
	db = *(++argv);
      }
    } else if(strcmp(*argv, "-a") == 0) {
      action = 1;
    } else if(strcmp(*argv, "-r") == 0) {
      action = 2;
    } else if(strcmp(*argv, "-m") == 0) {
      action = 3;
    } else if(argc >= 1 && strcmp(*argv,"-h") == 0) {
      usage(cmd);
    } else if(argc >= 1 && strcmp(*argv,"-?") == 0) {
      usage(cmd);
    } else if(argc >= 1 && strcmp(*argv,"-help") == 0) {
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

  entries = readDb(pool, db, key, action);

  if(action == 1) {
    // add
    int entrynr = apr_table_elts(entries)->nelts + 1;
    char *uid = NULL;
    char line[1024];
    char *pwdd = genPwd(pool);
    char *pwd;
    char *comment;
    char *ack;
    pwd_t *e = apr_pcalloc(pool, sizeof(pwd_t));
    printf("\n");
    while(!uid || !uid[0]) {
      printf(" user id                  : ");
      uid = gets(line);
    }
    e->name = apr_pstrdup(pool, uid);
    printf(" passphrase [%s]: ", pwdd);
    pwd = gets(line);
    if(!pwd || !pwd[0]) {
      pwd = pwdd;
    }
    e->pwd = apr_pstrdup(pool, pwd);
    printf(" comment                  : ");
    comment = gets(line);
    e->comment = apr_pstrdup(pool, comment);

    printf("\n %03d: [%s] %s (%s)\n\nadd this entry (y/n)? ",
	   entrynr,
	   e->name, e->pwd, e->comment);
    ack = gets(line);
    if(strcasecmp(ack, "y") == 0) {
      apr_table_addn(entries,
		     apr_psprintf(pool, "%03d", entrynr),
		     (char *)e);
      writeDb(pool, db, key, entries);
    }
  } else if(action == 2) {
    // remove
    pwd_t *e = NULL;
    char line[1024];
    char *id;
    int entrynr = 0;
    char *ack;
    printEntries(pool, entries);
    while(!entrynr) {
      printf("\nenter number of the entry to remove: ");
      id = gets(line);
      entrynr = atoi(id);
      e = (pwd_t *)apr_table_get(entries, apr_psprintf(pool, "%03d", entrynr));
      if(e == NULL) {
	entrynr = 0;
      }
    }
    if(e) {
      printf("\n %03d: [%s] %s (%s)\n\nremove this entry (y/n)? ",
	     entrynr,
	     e->name, e->pwd, e->comment);
      ack = gets(line);
      if(strcasecmp(ack, "y") == 0) {
	apr_table_unset(entries,
		       apr_psprintf(pool, "%03d", entrynr));
	writeDb(pool, db, key, entries);
      }
    }
  } else if(action == 3) {
    // change passphrase
    char *pwd = readPassword(pool, "enter new passphrase: ");
    char *pwdv = readPassword(pool, "re-enter your passphrase: ");
    if(strcmp(pwd, pwdv) == 0 && pwd[0]) {
      setKey(pool, pwd, key);
      writeDb(pool, db, key, entries);
    } else {
      fprintf(stderr, "ERROR, passphrase do not match\n");
      exit(1);
    }
    return 0;
  }
  printf("\n");
  printEntries(pool, entries);

  apr_pool_destroy(pool);
  return 0;
}
