/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * Quality of service module for Apache Web Server.
 *
 * The Apache Web Servers requires threads and processes to serve
 * requests. Each TCP connection to the web server occupies one
 * thread or process. Sometimes, a server gets too busy to serve
 * every request due the lack of free processes or threads.
 *
 * This module implements control mechanisms that can provide
 * different priority to different requests.
 *
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2007 Pascal Buchbinder
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

/************************************************************************
 * Version
 ***********************************************************************/

static const char revision[] = "$Id: mod_qos.c,v 3.1 2007-08-07 16:49:22 pbuchbinder Exp $";

/************************************************************************
 * Includes
 ***********************************************************************/

/* mod_qos requires OpenSSL */
#include <openssl/rand.h>
#include <openssl/evp.h>

/* apache */
#include <httpd.h>
#include <http_protocol.h>
#include <http_main.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_log.h>
#include <util_filter.h>
#include <time.h>
#include <ap_mpm.h>

/* apr */
#include <apr_strings.h>

/* additional modules */
#include "mod_status.h"

/************************************************************************
 * defines
 ***********************************************************************/
#define QOS_LOG_PFX "mod_qos: "
#define QOS_RAN 10
#define QOS_MAGIC_LEN 8
#define QOS_MAX_AGE "3600"
#define QOS_COOKIE_NAME "MODQOS"
#define QS_SIM_IP_LEN 100
#define QS_USR_SPE "mod_qos::user"
#define QS_STACK_SIZE 32768
static char qs_magic[QOS_MAGIC_LEN] = "qsmagic";

/************************************************************************
 * structures
 ***********************************************************************/

/**
 * user space
 */
typedef struct {
  int server_start;
} qos_user_t;

/**
 * ip entry
 */
typedef struct qs_ip_entry_st {
  unsigned long ip;
  int counter;
  struct qs_ip_entry_st* left;
  struct qs_ip_entry_st* right;
  struct qs_ip_entry_st* next;
} qs_ip_entry_t;

/**
 * connection data
 */
typedef struct qs_conn_st {
  int connections;
  qs_ip_entry_t *ip_tree;   /** ip tree main node */
  qs_ip_entry_t *ip_free;   /** ip node free list */
} qs_conn_t;

/**
 * session cookie
 */
typedef struct {
  unsigned char ran[QOS_RAN];
  char magic[QOS_MAGIC_LEN];
  time_t time;
} qos_session_t;

/** 
 * access control table entry
 */
typedef struct qs_acentry_st {
  int id;
  char *lock_file;
  apr_global_mutex_t *lock;
  int counter;
  int limit;
  struct qs_acentry_st *next;
  int url_len;
#ifdef AP_REGEX_H
  ap_regex_t *regex;
#else
  regex_t *regex;
#endif
  char *url;
} qs_acentry_t;

/**
 * access control table (act)
 */
typedef struct qs_actable_st {
  apr_size_t size;
  apr_shm_t *m;
  char *m_file;
  apr_pool_t *pool;
  apr_pool_t *ppool;
  qs_acentry_t *entry;      /** rule entry list */
  char *lock_file;
  apr_global_mutex_t *lock; /** ip/conn lock */
  qs_conn_t *c;
  int child_init;
  unsigned int timeout;
} qs_actable_t;

/**
 * server configuration
 */
typedef struct {
  apr_pool_t *pool;
  int is_virtual;
  server_rec *base_server;
  qs_actable_t *act;
  const char *error_page;
  apr_table_t *location_t;
  char *cookie_name;
  char *cookie_path;
  int max_age;
  unsigned char key[EVP_MAX_KEY_LENGTH];
  char *header_name;
  int max_conn;
  int max_conn_close;
  int max_conn_per_ip;
  apr_table_t *exclude_ip;
#ifdef QS_SIM_IP
  apr_table_t *testip;
#endif
} qos_srv_config;

/**
 * connection configuration
 */
typedef struct {
  unsigned long ip;
  conn_rec *c;
  char *evmsg;
  qos_srv_config *sconf;
} qs_conn_ctx;

/**
 * request configuration
 */
typedef struct {
  qs_acentry_t *entry;
  char *evmsg;
  int is_vip;
} qs_req_ctx;

/**
 * rule set
 */
typedef struct {
  char *url;
  int limit;
#ifdef AP_REGEX_H
  /* apache 2.2 */
  ap_regex_t *regex;
#else
  /* apache 2.0 */
  regex_t *regex;
#endif
} qs_rule_ctx_t;


/************************************************************************
 * globals
 ***********************************************************************/

module AP_MODULE_DECLARE_DATA qos_module;

/************************************************************************
 * private functions
 ***********************************************************************/

/**
 * extract the session cookie from the request
 */
static char *qos_get_remove_cookie(request_rec *r, qos_srv_config* sconf) {
  const char *cookie_h = apr_table_get(r->headers_in, "cookie");
  if(cookie_h) {
    char *cn = apr_pstrcat(r->pool, sconf->cookie_name, "=", NULL);
    char *p = ap_strcasestr(cookie_h, cn);
    if(p) {
      char *value = NULL;
      p[0] = '\0'; /* terminate the beginning of the cookie header */
      p = p + strlen(cn);
      value = ap_getword(r->pool, (const char **)&p, ';');
      while(p && (p[0] == ' ')) p++;
      /* skip a path, if there is any */
      if(p && (strncasecmp(p, "$path=", strlen("$path=")) == 0)) {
        ap_getword(r->pool, (const char **)&p, ';');
      }
      /* restore cookie header */
      cookie_h = apr_pstrcat(r->pool, cookie_h, p, NULL);
      if((strncasecmp(cookie_h, "$Version=", strlen("$Version=")) == 0) &&
         (strlen(cookie_h) <= strlen("$Version=X; "))) {
        /* nothing left */
        apr_table_unset(r->headers_in, "cookie");
      } else {
        apr_table_set(r->headers_in, "cookie", cookie_h);
      }
      return value;
    }
  }
  return NULL;
}

/**
 * verifies the session cookie 0=failed, 1=succeeded
 */
static int qos_verify_session(request_rec *r, qos_srv_config* sconf) {
  char *value = qos_get_remove_cookie(r, sconf);
  EVP_CIPHER_CTX cipher_ctx;
  if(value == NULL) return 0;

  {
    /* decode */
    char *dec = (char *)apr_palloc(r->pool, 1 + apr_base64_decode_len(value));
    int dec_len = apr_base64_decode(dec, value);
    if(dec_len == 0) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                    QOS_LOG_PFX"session cookie verification failed, invalid base64 encoding");
      return 0;
    }

    {
      /* decrypt */
      int len = 0;
      int buf_len = 0;
      unsigned char *buf = apr_pcalloc(r->pool, dec_len);
      EVP_CIPHER_CTX_init(&cipher_ctx);
      EVP_DecryptInit(&cipher_ctx, EVP_des_ede3_cbc(), sconf->key, NULL);
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
      if(buf_len != sizeof(qos_session_t)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                      QOS_LOG_PFX"session cookie verification failed, invalid size");
        return 0;
      } else {
        qos_session_t *s = (qos_session_t *)buf;
        s->magic[QOS_MAGIC_LEN] = '\0';
        if(strcmp(qs_magic, s->magic) != 0) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                        QOS_LOG_PFX"session cookie verification failed, invalid magic");
          return 0;
        }
        if(s->time < time(NULL) - sconf->max_age) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                        QOS_LOG_PFX"session cookie verification failed, expired");
          return 0;
        }
      }
    }

    /* success */
    return 1;
  
  failed:
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX"session cookie verification failed, could not decrypt data");
    return 0;
  }
}

/**
 * set/update the session cookie
 */
static void qos_set_session(request_rec *r, qos_srv_config *sconf) {
  qos_session_t *s = (qos_session_t *)apr_pcalloc(r->pool, sizeof(qos_session_t));
  EVP_CIPHER_CTX cipher_ctx;
  int buf_len = 0;
  int len = 0;
  unsigned char *buf = apr_pcalloc(r->pool, sizeof(qos_session_t) +
                                   EVP_CIPHER_block_size(EVP_des_ede3_cbc()));
    
  /* payload */
  strcpy(s->magic, qs_magic);
  s->magic[QOS_MAGIC_LEN] = '\0';
  s->time = time(NULL);
  RAND_bytes(s->ran, sizeof(s->ran));
  
  /* sym enc, should be sufficient for this use case */
  EVP_CIPHER_CTX_init(&cipher_ctx);
  EVP_EncryptInit(&cipher_ctx, EVP_des_ede3_cbc(), sconf->key, NULL);
  if(!EVP_EncryptUpdate(&cipher_ctx, &buf[buf_len], &len, (const unsigned char *)s, sizeof(qos_session_t))) {
    goto failed;
  }
  buf_len+=len;
  if(!EVP_EncryptFinal(&cipher_ctx, &buf[buf_len], &len)) {
    goto failed;
  }
  buf_len+=len;
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  
  /* encode and set data */
  {
    char *cookie;
    char *session = (char *)apr_pcalloc(r->pool, 1 + apr_base64_encode_len(buf_len));
    len = apr_base64_encode(session, (const char *)buf, buf_len);
    session[len] = '\0';
    cookie = apr_psprintf(r->pool, "%s=%s; Path=%s; Max-Age=%d",
                          sconf->cookie_name, session,
                          sconf->cookie_path, sconf->max_age);
    apr_table_add(r->headers_out,"Set-Cookie", cookie);
  }
  return;
  
 failed:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                QOS_LOG_PFX"failed to create session cookie");
}

/**
 * returns the request context
 */
static qs_req_ctx *qos_rctx_config_get(request_rec *r) {
  qs_req_ctx *rctx = ap_get_module_config(r->request_config, &qos_module);
  if(rctx == NULL) {
    rctx = apr_pcalloc(r->pool, sizeof(qs_req_ctx));
    rctx->entry = NULL;
    rctx->evmsg = NULL;
    rctx->is_vip = 0;
    ap_set_module_config(r->request_config, &qos_module, rctx);
  }
  return rctx;
}

/**
 * destroy shared memory and mutexes
 */
static void qos_destroy_act(qs_actable_t *act) {
  qs_acentry_t *e = act->entry;
  apr_os_thread_t tid = apr_os_thread_current();
  ap_log_error(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, NULL,
               QOS_LOG_PFX"cleanup shared memory: %d bytes [#%d(%d)]",
               act->size, getpid(), tid);
  act->child_init = 0;
  apr_global_mutex_destroy(act->lock);
  while(e) {
    apr_global_mutex_destroy(e->lock);
    e = e->next;
  }
  apr_shm_destroy(act->m);
  apr_pool_destroy(act->pool);
}

static qos_user_t *qos_get_user_conf(apr_pool_t *ppool) {
  void *v;
  qos_user_t *u;
  apr_pool_userdata_get(&v, QS_USR_SPE, ppool);
  if(v) return v;
  u = (qos_user_t *)apr_pcalloc(ppool, sizeof(qos_user_t));
  u->server_start = 0;
  apr_pool_userdata_set(u, QS_USR_SPE, apr_pool_cleanup_null, ppool);
  return u;
}

/**
 * deletes the act after the server timeout
 */
static void *qos_clean_thread(apr_thread_t *t ,void *p) {
  qs_actable_t *act = p;
  apr_os_thread_t tid = apr_os_thread_current();
  ap_log_error(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, NULL,
               QOS_LOG_PFX"start cleanup thread [#%d(%d)]", getpid(), tid);
  sleep(act->timeout);
  qos_destroy_act(act);
  return 0;
}

/**
 * well, we don't know if it is a graceful restart due we can't access
 * the mpm static varibale is_graceful. at least, we detect inital config
 * check start
 */
static int qos_is_graceful(qs_actable_t *act) {
  qos_user_t *u = qos_get_user_conf(act->ppool);
  if(u->server_start > 1) return 1;
  return 0;
}

/**
 * destroys the act
 * shared memory must not be destroyed before graceful restart has
 * been finished due running requests still need the shared memory
 * till they have finished.
 * try to keep memory leak as lttle as possible...
 */
static apr_status_t qos_cleanup_shm(void *p) {
  qs_actable_t *act = p;
  if(qos_is_graceful(act)) {
    apr_thread_t *tid;
    apr_pool_t *pool;
    apr_threadattr_t *attr;
    apr_pool_create(&pool, NULL);
    apr_threadattr_create(&attr, pool);
    apr_threadattr_detach_set(attr, 1);
    apr_threadattr_stacksize_set(attr, QS_STACK_SIZE);
    apr_thread_create(&tid, attr, qos_clean_thread, act, act->pool);
  } else {
    qos_destroy_act(act);
  }
  return APR_SUCCESS;
}

/**
 * init the shared memory act
 */
static apr_status_t qos_init_shm(server_rec *s, qs_actable_t *act, apr_table_t *table) {
  apr_status_t res;
  int i;
  int rule_entries = apr_table_elts(table)->nelts;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(table)->elts;
  qs_acentry_t *e = NULL;
  qs_ip_entry_t *ip = NULL;
  int server_limit, thread_limit, max_ip;
  ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
  ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
  if(thread_limit == 0) thread_limit = 1; // mpm prefork
  max_ip = thread_limit * server_limit;

  act->m_file = apr_psprintf(act->pool, "%s_m.mod_qos",
                             ap_server_root_relative(act->pool, tmpnam(NULL)));
  act->size = APR_ALIGN_DEFAULT(sizeof(qs_conn_t)) +
    (rule_entries * APR_ALIGN_DEFAULT(sizeof(qs_acentry_t))) +
    (max_ip * APR_ALIGN_DEFAULT(sizeof(qs_ip_entry_t)));
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, 
               QOS_LOG_PFX"%s(%s), create shared memory: %d bytes (r=%d,ip=%d)", 
               s->server_hostname == NULL ? "-" : s->server_hostname,
               s->is_virtual ? "v" : "b", act->size, rule_entries, max_ip);
  res = apr_shm_create(&act->m, (act->size + 512), act->m_file, act->pool);
  if (res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                 QOS_LOG_PFX"could not create shared memory: %s", buf);
    return res;
  }
  act->c = apr_shm_baseaddr_get(act->m);
  if(rule_entries) {
    act->entry = (qs_acentry_t *)&act->c[1];
    e = act->entry;
    act->c->ip_free = (qs_ip_entry_t *)&e[rule_entries];
  } else {
    act->entry = NULL;
    act->c->ip_free = (qs_ip_entry_t *)&act->c[1];
  }
  /* init rule entries (link data, init mutex) */
  for(i = 0; i < rule_entries; i++) {
    qs_rule_ctx_t *rule = (qs_rule_ctx_t *)entry[i].val;
    e->next = &e[1];
    e->id = i;
    e->url = rule->url;
    e->url_len = strlen(e->url);
    e->regex = rule->regex;
    e->limit = rule->limit;
    e->counter = 0;
    e->lock_file = apr_psprintf(act->pool, "%s_e%d.mod_qos", 
                                ap_server_root_relative(act->pool, tmpnam(NULL)), i);
    res = apr_global_mutex_create(&e->lock, e->lock_file, APR_LOCK_DEFAULT, act->pool);
    if (res != APR_SUCCESS) {
      char buf[MAX_STRING_LEN];
      apr_strerror(res, buf, sizeof(buf));
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                   QOS_LOG_PFX"could create mutex: %s", buf);
      return res;
    }
    if(i < rule_entries - 1) {
      e = e->next;
    } else {
      e->next = NULL;
    }
  }
  /* init free ip node list */
  ip = act->c->ip_free;
  for(i = 0; i < max_ip; i++) {
    ip->next = &ip[1];
    if(i < max_ip - 1) {
      ip = ip->next;
    } else {
      ip->next = NULL;
    }
  }
  return APR_SUCCESS;
}


static void qos_free_ip(qs_actable_t *act, qs_ip_entry_t *ipe) {
  ipe->next = act->c->ip_free;
  ipe->left = NULL;
  ipe->right = NULL;
  ipe->counter = 0;
  act->c->ip_free = ipe;
}

static qs_ip_entry_t *qos_new_ip(qs_actable_t *act) {
  qs_ip_entry_t *ipe = act->c->ip_free;
  act->c->ip_free = ipe->next;
  ipe->next = NULL;
  ipe->left = NULL;
  ipe->right = NULL;
  ipe->counter = 0;
  return ipe;
}

/**
 * adds an ip entry (insert or increment)
 * returns the number of entries
 */
static int qos_add_ip(apr_pool_t *p, qs_conn_ctx *cconf) {
  int num = 0;
  cconf->ip = inet_addr(cconf->c->remote_ip); /* v4 */
#ifdef QS_SIM_IP
  /* use one of the predefined ip addresses */
  {
    char *testid = apr_psprintf(p, "%d", rand()%(QS_SIM_IP_LEN-1));
    const char *testip = apr_table_get(cconf->sconf->testip, testid);
    cconf->ip = inet_addr(testip);
  }
#endif
  apr_global_mutex_lock(cconf->sconf->act->lock);   /* @CRT1 */
  {
    qs_ip_entry_t *ipe = cconf->sconf->act->c->ip_tree;
    if(ipe == NULL) {
      ipe = qos_new_ip(cconf->sconf->act);
      ipe->ip = cconf->ip;
      ipe->counter = 0;
      cconf->sconf->act->c->ip_tree = ipe;
    } else {
      qs_ip_entry_t *last;
      while(ipe->ip != cconf->ip) {
        last = ipe;
        if(cconf->ip > ipe->ip) {
          ipe = ipe->right;
        } else {
          ipe = ipe->left;
        }
        if(ipe == NULL) {
          ipe = qos_new_ip(cconf->sconf->act);
          ipe->ip = cconf->ip;
          if(ipe->ip > last->ip) {
            last->right = ipe;
          } else {
            last->left = ipe;
          }
          break;
        }
      }
    }
    ipe->counter++;
    num = ipe->counter;
  }
  apr_global_mutex_unlock(cconf->sconf->act->lock); /* @CRT1 */
  return num;
}

static void qos_insert_ip(qs_ip_entry_t *root, qs_ip_entry_t *re) {
  qs_ip_entry_t *ipe = re;
  qs_ip_entry_t *last = root;
  while(last) {
    if(ipe->ip > last->ip) {
      if(last->right == NULL) {
        last->right = ipe;
        last = NULL;
      } else {
        last = last->right;
      }
    } else {
      if(last->left == NULL) {
        last->left = ipe;
        last = NULL;
      } else {
        last = last->left;
      }
    }
  }
}

/**
 * removes an ip entry (delete or decrement)
 */
static void qos_remove_ip(qs_conn_ctx *cconf) {
  apr_global_mutex_lock(cconf->sconf->act->lock);   /* @CRT2 */
  {
    qs_ip_entry_t *ipe = cconf->sconf->act->c->ip_tree;
    qs_ip_entry_t *last = NULL;
    qs_ip_entry_t *re;
    int right = 0;
    /* find entry ... */
    while(ipe->ip != cconf->ip) {
      last = ipe;
      if(cconf->ip > ipe->ip) {
        ipe = ipe->right;
        right = 1;
      } else {
        ipe = ipe->left;
        right = 0;
      }
    }
    ipe->counter--;
    if(ipe->counter == 0) {
      if(last == NULL) {
        if(ipe->right) {
          cconf->sconf->act->c->ip_tree = ipe->right;
          re = ipe->left;
        } else {
          cconf->sconf->act->c->ip_tree = ipe->left;
          re = ipe->right;
        }
        last = cconf->sconf->act->c->ip_tree;
      } else {
        if(right) {
          last->right = ipe->right;
          re = ipe->left;
        } else {
          last->left = ipe->right;
          re = ipe->left;
        }
      }
      qos_free_ip(cconf->sconf->act, ipe);
      if(last && re) qos_insert_ip(last, re);
    }
  }
  apr_global_mutex_unlock(cconf->sconf->act->lock); /* @CRT2 */
}

/**
 * send server error, used for connection errors
 */
static int qos_return_error(conn_rec *c) {
  char *line = apr_pstrcat(c->pool, AP_SERVER_PROTOCOL, " ",
                           ap_get_status_line(500), CRLF CRLF, NULL);
  apr_bucket *e = apr_bucket_pool_create(line, strlen(line), c->pool, c->bucket_alloc);
  apr_bucket_brigade *bb = apr_brigade_create(c->pool, c->bucket_alloc);
  APR_BRIGADE_INSERT_HEAD(bb, e);
  e = apr_bucket_flush_create(c->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bb, e);
  ap_pass_brigade(c->output_filters, bb);
  return HTTP_INTERNAL_SERVER_ERROR;
}

/**
 * returns custom error page
 */
static void qos_error_response(request_rec *r, const char *error_page) {
  /* do (almost) the same as ap_die() does */
  const char *error_notes;
  r->status = HTTP_INTERNAL_SERVER_ERROR;
  r->connection->keepalive = AP_CONN_CLOSE;
  r->no_local_copy = 1;
  apr_table_setn(r->subprocess_env, "REQUEST_METHOD", r->method);
  if ((error_notes = apr_table_get(r->notes, 
                                   "error-notes")) != NULL) {
    apr_table_setn(r->subprocess_env, "ERROR_NOTES", error_notes);
  }
  r->method = apr_pstrdup(r->pool, "GET");
  r->method_number = M_GET;
  ap_internal_redirect(error_page, r);
}

/**
 * returns the matching regex with the lowest limitation
 */
static qs_acentry_t *qos_getrule_byregex(request_rec *r, qos_srv_config *sconf) {
  qs_acentry_t *ret = NULL;
  qs_actable_t *act = sconf->act;
  qs_acentry_t *e = act->entry;
  int limit = -1;
  while(e) {
    if(e->regex != NULL) {
      if((limit == -1) || (e->limit < limit)) {
        if(ap_regexec(e->regex, r->unparsed_uri, 0, NULL, 0) == 0) {
          if(limit == -1) {
            ret = e;
            limit = e->limit;
          } else if(e->limit < limit) {
            ret = e;
            limit = e->limit;
          }
        }
      }
    }
    e = e->next;
  }
  return ret;
}

/**
 * returns the best matching location entry
 */
static qs_acentry_t *qos_getrule_bylocation(request_rec * r, qos_srv_config *sconf) {
  qs_acentry_t *ret = NULL;
  qs_actable_t *act = sconf->act;
  qs_acentry_t *e = act->entry;
  int match_len = 0;
  while(e) {
    if(e->regex == NULL) {
      /* per location limitation */
      if(strncmp(e->url, r->parsed_uri.path, e->url_len) == 0) {
        /* best match */
        if(e->url_len > match_len) {
          match_len = e->url_len;
          ret = e;
        }
      }
    }
    e = e->next;
  }
  return ret;
}

/**
 * checks for VIP user (may pass restrictions)
 */
static int qos_is_vip(request_rec *r, qos_srv_config *sconf) {
  if(qos_verify_session(r, sconf)) {
    return 1;
  }
  if (r->subprocess_env) {
    const char *v = apr_table_get(r->subprocess_env, "QS_VipRequest");
    if(v && (strcasecmp(v, "yes") == 0)) {
      return 1;
    }
  }
  return 0;
}

/************************************************************************
 * "public"
 ***********************************************************************/
static int qos_ext_status_hook(request_rec *r, int flags) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  server_rec *s = sconf->base_server;
  if (flags & AP_STATUS_SHORT)
    return OK;

  ap_rputs("<hr>\n", r);
  ap_rputs("<h2>mod_qos</h2>\n", r);
  while(s) {
    qs_acentry_t *e;
    ap_rprintf(r, "<h3>%s:%d (%s)</h3>\n",
               s->server_hostname == NULL ? "-" : s->server_hostname,
               s->addrs->host_port,
               s->is_virtual ? "virtual" : "base");
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    if(sconf && sconf->act) {
      e = sconf->act->entry;
      ap_rputs("<p><table border=\"1\">\n", r);
      ap_rputs("<tr><td>rule</td><td>limit</td><td>current</td></tr>\n", r);
      while(e) {
        ap_rputs("<tr>\n", r);
        ap_rprintf(r, "<td>%s</td>\n", e->url);
        ap_rprintf(r, "<td>%d</td>\n", e->limit);
        ap_rprintf(r, "<td>%d</td>\n", e->counter);
        ap_rputs("</tr>\n", r);
        e = e->next;
      }
      ap_rputs("</table></p>\n", r);
    }
    if(sconf) {
      qs_ip_entry_t *f;
      int c = 0;
      apr_global_mutex_lock(sconf->act->lock);   /* @CRT7 */
      f = sconf->act->c->ip_free;
      while(f) {
        c++;
        f = f->next;
      }
      apr_global_mutex_unlock(sconf->act->lock); /* @CRT7 */
      ap_rprintf(r,"<p>free ip entries: %d<br>", c);
      ap_rprintf(r,"max connections: %d<br>", sconf->max_conn);
      ap_rprintf(r,"max connections with keep-alive: %d<br>", sconf->max_conn_close);
      ap_rprintf(r,"max connections per client: %d</p>", sconf->max_conn_per_ip);

    }

    s = s->next;
  }
  return OK;
}


/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * connection destructor
 */
static apr_status_t qos_cleanup_conn(void *p) {
  qs_conn_ctx *cconf = p;
  if(cconf->sconf->max_conn != -1) {
    apr_global_mutex_lock(cconf->sconf->act->lock);   /* @CRT3 */
    cconf->sconf->act->c->connections--;
    apr_global_mutex_unlock(cconf->sconf->act->lock); /* @CRT3 */
  }
  if(cconf->sconf->max_conn_per_ip != -1) {
    qos_remove_ip(cconf);
  }
  return APR_SUCCESS;
}

/**
 * connection constructor
 */
static int qos_process_connection(conn_rec * c) {
  qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(c->conn_config, &qos_module);
  int vip = 0;
  if(cconf == NULL) {
    int connections;
    int current;
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(c->base_server->module_config,
                                                                  &qos_module);
    cconf = apr_pcalloc(c->pool, sizeof(qs_conn_ctx));
    cconf->c = c;
    cconf->evmsg = NULL;
    cconf->sconf = sconf;
    ap_set_module_config(c->conn_config, &qos_module, cconf);
    apr_pool_cleanup_register(c->pool, cconf, qos_cleanup_conn, apr_pool_cleanup_null);

    /* update data */
    if(sconf->max_conn != -1) {
      apr_global_mutex_lock(cconf->sconf->act->lock);  /* @CRT4 */
      cconf->sconf->act->c->connections++;
      connections = cconf->sconf->act->c->connections; /* @CRT4 */
      apr_global_mutex_unlock(cconf->sconf->act->lock);
    }
    if(sconf->max_conn_per_ip != -1) {
      current = qos_add_ip(c->pool, cconf);
    }

    /* check for vip */
    if(apr_table_elts(sconf->exclude_ip)->nelts > 0) {
      int i;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->exclude_ip)->elts;
      for(i = 0; i < apr_table_elts(sconf->exclude_ip)->nelts; i++) {
        if(strncmp(entry[i].key, cconf->c->remote_ip, strlen(entry[i].key)) == 0) {
          vip = 1;
          cconf->evmsg = apr_pstrcat(c->pool, "S;", cconf->evmsg, NULL);
        }
      }
    }

    /* enforce rules */
    if((sconf->max_conn != -1) && !vip) {
      if(connections > sconf->max_conn) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                     QOS_LOG_PFX"access denied, rule: max=%d, concurrent connections=%d, c=%s",
                     sconf->max_conn, connections,
                     c->remote_ip == NULL ? "-" : c->remote_ip);
        c->keepalive = AP_CONN_CLOSE;
        return qos_return_error(c);
      }
    }
    if((sconf->max_conn_per_ip != -1) && !vip) {
      if(current > sconf->max_conn_per_ip) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                     QOS_LOG_PFX"access denied, rule: max_ip=%d, concurrent connections=%d, c=%s",
                     sconf->max_conn_per_ip, current,
                     c->remote_ip == NULL ? "-" : c->remote_ip);
        c->keepalive = AP_CONN_CLOSE;
        return qos_return_error(c);
      }
    }
  }
  return DECLINED;
}

/**
 * header parser implements restrictions on a per location (url) basis.
 */
static int qos_header_parser(request_rec * r) {
  /* apply rules only to main request (avoid filtering of error documents) */
  if(ap_is_initial_req(r)) {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);

    /*
     * QS_LocRequestLimitMatch/QS_LocRequestLimit/QS_LocRequestLimitDefault enforcement
     */
    /* 1st prio has QS_LocRequestLimitMatch */
    qs_acentry_t *e = qos_getrule_byregex(r, sconf);
    /* 2th prio has QS_LocRequestLimit */
    if(!e) e = qos_getrule_bylocation(r, sconf);
    if(e) {
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      rctx->entry = e;
      apr_global_mutex_lock(e->lock);   /* @CRT5 */
      e->counter++;
      apr_global_mutex_unlock(e->lock); /* @CRT5 */
      
      /* enforce the limitation */
      if(e->counter > e->limit) {
        /* vip session has no limitation */
        if(sconf->header_name) {
          rctx->is_vip = qos_is_vip(r, sconf);
          if(rctx->is_vip) {
            rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
            return DECLINED;
          }
        }        
        /* std user */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOS_LOG_PFX"access denied, rule: %s(%d), concurrent requests=%d, c=%s",
                      e->url, e->limit, e->counter,
                      r->connection->remote_ip == NULL ? "-" : r->connection->remote_ip);
        rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
        if(sconf->error_page) {
          qos_error_response(r, sconf->error_page);
          return DONE;
        }
        return HTTP_INTERNAL_SERVER_ERROR;
      }
    }
  }
  return DECLINED;
}

/**
 * process response:
 * - detects vip header and create session
 */
static apr_status_t qos_out_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  if(sconf->header_name) {
    const char *ctrl_h = apr_table_get(r->headers_out, sconf->header_name);
    if(ctrl_h) {
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      qos_set_session(r, sconf);
      rctx->evmsg = apr_pstrcat(r->pool, "V;", rctx->evmsg, NULL);
      apr_table_unset(r->headers_out, sconf->header_name);
    }
  }
  if(sconf->max_conn_close != -1) {
    if(sconf->act->c->connections > sconf->max_conn_close) {
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      rctx->evmsg = apr_pstrcat(r->pool, "K;", rctx->evmsg, NULL);
      r->connection->keepalive = AP_CONN_CLOSE;
    }
  }
  ap_remove_output_filter(f);
  return ap_pass_brigade(f->next, bb); 
}

/**
 * "free resources"
 */
static int qos_logger(request_rec * r) {
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  qs_acentry_t *e = rctx->entry;
  qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config, &qos_module);
  if(cconf && cconf->evmsg) {
    rctx->evmsg = apr_pstrcat(r->pool, cconf->evmsg, rctx->evmsg, NULL);
  }
  if(e) {
    char *h = apr_psprintf(r->pool, "%d", e->counter);
    apr_global_mutex_lock(e->lock);   /* @CRT6 */
    e->counter--;
    apr_global_mutex_unlock(e->lock); /* @CRT6 */
    /* alow logging of the current location usage */
    apr_table_set(r->headers_out, "mod_qos_cr", h);
    apr_table_set(r->err_headers_out, "mod_qos_cr", h);
    if(r->next) {
      apr_table_set(r->next->headers_out, "mod_qos_cr", h);
      apr_table_set(r->next->err_headers_out, "mod_qos_cr", h);
    }
    /* decrement only once */
    ap_set_module_config(r->request_config, &qos_module, NULL);
  }
  if(rctx->evmsg) {
    apr_table_set(r->headers_out, "mod_qos_ev", rctx->evmsg);
    apr_table_set(r->err_headers_out, "mod_qos_ev", rctx->evmsg);
    if(r->next) {
      apr_table_set(r->next->headers_out, "mod_qos_ev", rctx->evmsg);
      apr_table_set(r->next->err_headers_out, "mod_qos_ev", rctx->evmsg);
    }
  }
  return DECLINED;
}

/**
 * inits each child
 */
static void qos_child_init(apr_pool_t *p, server_rec *bs) {
  server_rec *s = bs->next;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  qs_acentry_t *e = sconf->act->entry;
  if(!sconf->act->child_init) {
    sconf->act->child_init = 1;
    apr_global_mutex_child_init(&sconf->act->lock, sconf->act->lock_file, sconf->act->pool);
    while(e) {
      /* attach to the mutex */
      apr_global_mutex_child_init(&e->lock, e->lock_file, sconf->act->pool);
      e = e->next;
    }
    while(s) {
      sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
      if(sconf->is_virtual) {
        apr_global_mutex_child_init(&sconf->act->lock, sconf->act->lock_file, sconf->act->pool);
        e = sconf->act->entry;
        while(e) {
          apr_global_mutex_child_init(&e->lock, e->lock_file, sconf->act->pool);
          e = e->next;
        }
      }
      s = s->next;
    }
  }
}

/**
 * inits the server configuration
 */
static int qos_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *bs) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  char *rev = apr_pstrdup(ptemp, "$Revision: 3.1 $");
  char *er = strrchr(rev, ' ');
  server_rec *s = bs->next;
  int rules = 0;
  qos_user_t *u = qos_get_user_conf(s->process->pool);
  u->server_start++;
  er[0] = '\0';
  rev++;
  sconf->base_server = bs;
  sconf->act->timeout = apr_time_sec(bs->timeout);
  if(sconf->act->timeout == 0) sconf->act->timeout = 300;
  if(qos_init_shm(bs, sconf->act, sconf->location_t) != APR_SUCCESS) {
    return !OK;
  }
  apr_pool_cleanup_register(sconf->pool, sconf->act,
                            qos_cleanup_shm, apr_pool_cleanup_null);
  rules = apr_table_elts(sconf->location_t)->nelts;
  while(s) {
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    sconf->base_server = bs;
    sconf->act->timeout = apr_time_sec(s->timeout);
    if(sconf->act->timeout == 0) sconf->act->timeout = 300;
    if(sconf->is_virtual) {
      if(qos_init_shm(s, sconf->act, sconf->location_t) != APR_SUCCESS) {
        return !OK;
      }
      apr_pool_cleanup_register(sconf->pool, sconf->act,
                                qos_cleanup_shm, apr_pool_cleanup_null);
      rules = rules + apr_table_elts(sconf->location_t)->nelts;
    }
    s = s->next;
  }
  ap_log_error(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, bs,
               QOS_LOG_PFX"%s loaded (%d req rules)", rev, rules);

  APR_OPTIONAL_HOOK(ap, status_hook, qos_ext_status_hook, NULL, NULL, APR_HOOK_MIDDLE);

  return DECLINED;
}

/**
 * insert response filter
 */
static void qos_insert_filter(request_rec *r) {
  ap_add_output_filter("qos-out-filter", NULL, r, r->connection);
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
static void *qos_srv_config_create(apr_pool_t *p, server_rec *s) {
  qos_srv_config *sconf;
  apr_status_t rv;
  apr_pool_t *act_pool;
  apr_pool_create(&act_pool, NULL);
  sconf =(qos_srv_config *)apr_pcalloc(p, sizeof(qos_srv_config));
  sconf->pool = p;
  sconf->location_t = apr_table_make(sconf->pool, 2);
  sconf->error_page = NULL;
  sconf->act = (qs_actable_t *)apr_pcalloc(act_pool, sizeof(qs_actable_t));
  sconf->act->pool = act_pool;
  sconf->act->ppool = s->process->pool;
  sconf->act->m_file = NULL;
  sconf->act->child_init = 0;
  sconf->act->timeout = apr_time_sec(s->timeout);
  sconf->act->lock_file = apr_psprintf(sconf->act->pool, "%s.mod_qos",
                                       ap_server_root_relative(sconf->act->pool, tmpnam(NULL)));
  rv = apr_global_mutex_create(&sconf->act->lock, sconf->act->lock_file,
                               APR_LOCK_DEFAULT, sconf->act->pool);
  if (rv != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(rv, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                 QOS_LOG_PFX"could create mutex: %s", buf);
    exit(1);
  }
  sconf->is_virtual = s->is_virtual;
  sconf->cookie_name = apr_pstrdup(sconf->pool, QOS_COOKIE_NAME);
  sconf->cookie_path = apr_pstrdup(sconf->pool, "/");
  sconf->max_age = atoi(QOS_MAX_AGE);
  sconf->header_name = NULL;
  sconf->max_conn = -1;
  sconf->max_conn_close = -1;
  sconf->max_conn_per_ip = -1;
  sconf->exclude_ip = apr_table_make(sconf->pool, 2);
  {
    int len = EVP_MAX_KEY_LENGTH;
    unsigned char *rand = apr_pcalloc(p, len);
    RAND_bytes(rand, len);
    EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL, rand, len, 1, sconf->key, NULL);
  }
#ifdef QS_SIM_IP
  {
    int i;
    sconf->testip = apr_table_make(sconf->pool, QS_SIM_IP_LEN);
    for(i = 0; i < QS_SIM_IP_LEN; i++) {
      char *qsmi = apr_psprintf(p, "%d.%d.%d.%d", rand()%255, rand()%255, rand()%255, rand()%255);
      apr_table_add(sconf->testip, apr_psprintf(p, "%d", i), qsmi);
    }
  }
#endif
  return sconf;
}

/**
 * "merges" server configuration: virtual host overwrites global settings (if
 * any rule has been specified)
 */
static void *qos_srv_config_merge(apr_pool_t * p, void *basev, void *addv) {
  qos_srv_config *b = (qos_srv_config *)basev;
  qos_srv_config *o = (qos_srv_config *)addv;
  if((apr_table_elts(o->location_t)->nelts > 0) ||
     (o->max_conn != -1)) {
    return o;
  }
  return b;
}

/**
 * command to define the concurrent request limitation for a location
 */
const char *qos_loc_con_cmd(cmd_parms * cmd, void *dcfg, const char *loc, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *id = apr_psprintf(cmd->pool, "%d", apr_table_elts(sconf->location_t)->nelts);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  rule->url = apr_pstrdup(cmd->pool, loc);
  rule->limit = atoi(limit);
  rule->regex = NULL;
  apr_table_setn(sconf->location_t, id, (char *)rule);
  return NULL;
}

/**
 * defines the maximum of concurrent requests matching the specified
 * request line pattern
 */
const char *qos_match_con_cmd(cmd_parms * cmd, void *dcfg, const char *match, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *id = apr_psprintf(cmd->pool, "%d", apr_table_elts(sconf->location_t)->nelts);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  rule->url = apr_pstrdup(cmd->pool, match);
  rule->limit = atoi(limit);
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  apr_table_setn(sconf->location_t, id, (char *)rule);
  return NULL;
}

/**
 * sets the default limitation of cuncurrent requests
 */
const char *qos_loc_con_def_cmd(cmd_parms * cmd, void *dcfg, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  return qos_loc_con_cmd(cmd, dcfg, "/", limit);
}

/**
 * defines custom error page
 */
const char *qos_error_page_cmd(cmd_parms * cmd, void *dcfg, const char *path) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->error_page = apr_pstrdup(cmd->pool, path);
  if(sconf->error_page[0] != '/') {
    return apr_psprintf(cmd->pool, "%s: requires absolute path (%s)", 
                        cmd->directive->directive, sconf->error_page);
  }
  return NULL;
}

/**
 * session definitions: cookie name and path, expiration/max-age
 */
const char *qos_cookie_name_cmd(cmd_parms * cmd, void *dcfg, const char *name) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->cookie_name = apr_pstrdup(cmd->pool, name);
  return NULL;
}

const char *qos_cookie_path_cmd(cmd_parms * cmd, void *dcfg, const char *path) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->cookie_path = apr_pstrdup(cmd->pool, path);
  return NULL;
}

const char *qos_timeout_cmd(cmd_parms * cmd, void *dcfg, const char *sec) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_age = atoi(sec);
  return NULL;
}

const char *qos_key_cmd(cmd_parms * cmd, void *dcfg, const char *seed) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL,
                 (const unsigned char *)seed, strlen(seed), 1, sconf->key, NULL);
  return NULL;
}

/**
 * name of the http header to mark a vip
 */
const char *qos_header_name_cmd(cmd_parms * cmd, void *dcfg, const char *name) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->header_name = apr_pstrdup(cmd->pool, name);
  return NULL;
}

/**
 * max concurrent connections per server
 */
const char *qos_max_conn_cmd(cmd_parms * cmd, void *dcfg, const char *number) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_conn = atoi(number);
  return NULL;
}

/**
 * disable keep-alive
 */
const char *qos_max_conn_close_cmd(cmd_parms * cmd, void *dcfg, const char *number) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_conn_close = atoi(number);
  return NULL;
}

/**
 * max concurrent connections per client ip
 */
const char *qos_max_conn_ip_cmd(cmd_parms * cmd, void *dcfg, const char *number) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_conn_per_ip = atoi(number);
  return NULL;
}

/**
 * ip address without any limitation
 */
const char *qos_max_conn_ex_cmd(cmd_parms * cmd, void *dcfg, const char *addr) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  apr_table_add(sconf->exclude_ip, addr, "e");
  return NULL;
}

static const command_rec qos_config_cmds[] = {
  /* request limitation per location */
  AP_INIT_TAKE2("QS_LocRequestLimit", qos_loc_con_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestLimit <location> <number>, defines the number of"
                " concurrent requests to the location. Default is defined by the"
                " QS_LocRequestLimitDefault directive."),
  AP_INIT_TAKE1("QS_LocRequestLimitDefault", qos_loc_con_def_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestLimitDefault <number>, defines the default for the"
                " QS_LocRequestLimit and QS_LocRequestLimitMatch directive."),
  AP_INIT_TAKE2("QS_LocRequestLimitMatch", qos_match_con_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestLimitMatch <regex> <number>, defines the number of"
                " concurrent requests to the request line pattern."
                " Default is defined by the QS_LocRequestLimitDefault directive."),
  /* error document */
  AP_INIT_TAKE1("QS_ErrorPage", qos_error_page_cmd, NULL,
                RSRC_CONF,
                "QS_ErrorPage <url>, defines a custom error page."),
  /* vip session */
  AP_INIT_TAKE1("QS_SessionCookieName", qos_cookie_name_cmd, NULL,
                RSRC_CONF,
                "QS_SessionCookieName <name>, defines a custom session cookie name,"
                " default is "QOS_COOKIE_NAME"."),
  AP_INIT_TAKE1("QS_SessionCookiePath", qos_cookie_path_cmd, NULL,
                RSRC_CONF,
                "QS_SessionCookiePath <path>, default it \"/\"."),
  AP_INIT_TAKE1("QS_SessionTimeout", qos_timeout_cmd, NULL,
                RSRC_CONF,
                "QS_SessionTimeout <seconds>, defines vip session life time,"
                " default are "QOS_MAX_AGE" seconds."),
  AP_INIT_TAKE1("QS_SessionKey", qos_key_cmd, NULL,
                RSRC_CONF,
                "QS_SessionKey <string>, defines a key used for session"
                " cookie encryption."),
  AP_INIT_TAKE1("QS_VipHeaderName", qos_header_name_cmd, NULL,
                RSRC_CONF,
                "QS_VipHeaderName <name>, defines the http header name which is"
                " used to signalize a very important person (vip)."),
  /* connection limitations */
  AP_INIT_TAKE1("QS_SrvMaxConn", qos_max_conn_cmd, NULL,
                RSRC_CONF,
                "QS_SrvMaxConn <number>, defines the maximum number of"
                " concurrent TCP connections for this server."),
  AP_INIT_TAKE1("QS_SrvMaxConnClose", qos_max_conn_close_cmd, NULL,
                RSRC_CONF,
                "QS_SrvMaxConnClose <number>, defines the maximum number of"
                " concurrent TCP connections until the server disables"
                " keep-alive for this server (closes the connection after"
                " each requests."),
  AP_INIT_TAKE1("QS_SrvMaxConnPerIP", qos_max_conn_ip_cmd, NULL,
                RSRC_CONF,
                "QS_SrvMaxConnPerIP <number>, defines the maximum number of"
                " concurrent TCP connections per IP source address "
                " (IP v4 only)."),
  AP_INIT_TAKE1("QS_SrvMaxConnExcludeIP", qos_max_conn_ex_cmd, NULL,
                RSRC_CONF,
                "QS_SrvMaxConnExcludeIP <addr>, excludes an ip address or"
                " address range from beeing limited."),
  NULL,
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void qos_register_hooks(apr_pool_t * p) {
  ap_hook_post_config(qos_post_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_child_init(qos_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_process_connection(qos_process_connection, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_header_parser(qos_header_parser, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(qos_logger, NULL, NULL, APR_HOOK_FIRST);

  ap_register_output_filter("qos-out-filter", qos_out_filter, NULL, AP_FTYPE_RESOURCE);
  ap_hook_insert_filter(qos_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);

}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA qos_module ={ 
  STANDARD20_MODULE_STUFF,
  NULL,                                     /**< dir config creater */
  NULL,                                     /**< dir merger */
  qos_srv_config_create,                    /**< server config */
  qos_srv_config_merge,                     /**< server merger */
  qos_config_cmds,                          /**< command table */
  qos_register_hooks,                       /**< hook registery */
};
