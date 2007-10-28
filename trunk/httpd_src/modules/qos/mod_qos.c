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
static const char revision[] = "$Id: mod_qos.c,v 4.24 2007-10-28 21:22:39 pbuchbinder Exp $";

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
#include <scoreboard.h>
#include <pcre.h>

/* apr */
#include <apr_strings.h>

/* additional modules */
#include "mod_status.h"

/************************************************************************
 * defines
 ***********************************************************************/
#define QOS_LOG_PFX(id)  "mod_qos("#id"): "
#define QOS_RAN 10
#define QOS_MAGIC_LEN 8
#define QOS_MAX_AGE "3600"
#define QOS_COOKIE_NAME "MODQOS"
#define QS_SIM_IP_LEN 100
#define QS_USR_SPE "mod_qos::user"
static char qs_magic[QOS_MAGIC_LEN] = "qsmagic";

/************************************************************************
 * structures
 ***********************************************************************/

typedef enum  {
  QS_CONN_STATE_NEW,
  QS_CONN_STATE_SHORT,
  QS_CONN_STATE_END
} qs_conn_state_e;

typedef enum  {
  QS_DENY_REQUEST_LINE,
  QS_DENY_PATH,
  QS_DENY_QUERY,
  QS_PERMIT_URI
} qs_rfilter_type_e;

typedef enum  {
  QS_LOG,
  QS_DENY
} qs_rfilter_action_e;

/**
 */
typedef struct {
  pcre *pr;
  char *text;
  char *id;
  qs_rfilter_type_e type;
  qs_rfilter_action_e action;
} qos_rfilter_t;

/**
 * in_filter ctx
 */
typedef struct {
  apr_socket_t *client_socket;
  apr_interval_time_t at;
  apr_interval_time_t qt;
  apr_interval_time_t server_timeout;
  qs_conn_state_e status;
} qos_ifctx_t;


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
  /** location rules */
  char *url;
  int url_len;
#ifdef AP_REGEX_H
  ap_regex_t *regex;
#else
  regex_t *regex;
#endif
  int counter;
  int limit;
  /* measurement */
  time_t interval;
  long req;
  long req_per_sec;
  long req_per_sec_limit;
  int req_per_sec_block_rate;
  long bytes;
  long kbytes_per_sec;
  long kbytes_per_sec_limit;
  int kbytes_per_sec_block_rate;
  struct qs_acentry_st *next;
} qs_acentry_t;

/**
 * access control table (act)
 */
typedef struct qs_actable_st {
  apr_size_t size;
  apr_shm_t *m;
  char *m_file;
  apr_pool_t *pool;
  /** process pool is used to create user space data */
  apr_pool_t *ppool;
  /** rule entry list */
  qs_acentry_t *entry;
  /** ip/conn data */
  char *lock_file;
  apr_global_mutex_t *lock;
  qs_conn_t *c;
  unsigned int timeout;
  /* settings */
  int child_init;
  int generation;
} qs_actable_t;

/**
 * user space
 */
typedef struct {
  int server_start;
  apr_table_t *act_table;
} qos_user_t;

typedef struct {
  apr_table_t *rfilter_table;
  int inheritoff;
  int headerfilter;
} qos_dir_config;

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
  int connect_timeout;
  apr_table_t *hfilter_table;
#ifdef QS_INTERNAL_TEST
  apr_table_t *testip;
  int enable_testip;
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
  long req_per_sec_limit;
  long kbytes_per_sec_limit;
} qs_rule_ctx_t;

typedef struct {
  const char* name;
  const char* pcre;
} qos_hel_t;

/************************************************************************
 * globals
 ***********************************************************************/

module AP_MODULE_DECLARE_DATA qos_module;

/************************************************************************
 * private functions
 ***********************************************************************/

/* simple header rules allowing "the usual" header formats only (even drop requests using
   extensions which are used rarely) */
/* reserved (to be escaped): {}[]()^$.|*+?\ */
static const qos_hel_t qs_header_rules[] = {
#define QS_URL_UNRESERVED  "a-zA-Z0-9-\\._~% "
#define QS_URL_GEN         ":/\\?#\\[\\]@"
#define QS_URL_SUB         "!$&'\\(\\)\\*\\+,;="
#define QS_URL             "["QS_URL_UNRESERVED""QS_URL_GEN""QS_URL_SUB"]"
#define QS_B64_SP          "[a-zA-Z0-9 \\+/\\$=:]"
#define QS_H_ACCEPT        "[a-zA-Z0-9\\-_\\*\\+]+/[a-zA-Z0-9\\-_\\*\\+]+(;[ ]?[a-zA-Z0-9]+=[0-9]+)?[ ]?(;[ ]?q=[0-9\\.]+)?"
#define QS_H_ACCEPT_C      "[a-zA-Z0-9\\-\\*]+(;[ ]?q=[0-9\\.]+)?"
#define QS_H_ACCEPT_E      "[a-zA-Z0-9\\-\\*]+(;[ ]?q=[0-9\\.]+)?"
#define QS_H_ACCEPT_L      "[a-zA-Z\\-\\*]+(;[ ]?q=[0-9\\.]+)?"
#define QS_H_CACHE         "no-cache|no-store|max-age=[0-9]+|max-stale(=[0-9]+)?|min-fresh=[0-9]+|no-transform|only-if-chached"
#define QS_H_CONTENT       "[a-zA-Z0-9\\-\\*/; =]+"
#define QS_H_COOKIE        "["QS_URL_UNRESERVED""QS_URL_GEN""QS_URL_SUB" ]"
#define QS_H_EXPECT        "[a-zA-Z0-9\\-= ;\\.,]"
#define QS_H_PRAGMA        "[a-zA-Z0-9\\-= ;\\.,]"
#define QS_H_FROM          "[a-zA-Z0-9\\-=@;\\.,\\(\\)]"
#define QS_H_HOST          "[a-zA-Z0-9\\-:\\.]"
#define QS_H_IFMATCH       "[a-zA-Z0-9\\-=@;\\.,\\*\"]"
#define QS_H_DATE          "[a-zA-Z0-9 :,]"
#define QS_H_TE            "[a-zA-Z0-9\\-\\*]+(;[ ]?q=[0-9\\.]+)?"
  { "Accept", "^("QS_H_ACCEPT"){1}(,[ ]?"QS_H_ACCEPT")*$" },
  { "Accept-Charset", "^("QS_H_ACCEPT_C"){1}(,[ ]?"QS_H_ACCEPT_C")*$" },
  { "Accept-Encoding", "^("QS_H_ACCEPT_E"){1}(,[ ]?"QS_H_ACCEPT_E")*$" },
  { "Accept-Language", "^("QS_H_ACCEPT_L"){1}(,[ ]?"QS_H_ACCEPT_L")*$" },
  { "Authorization", "^"QS_B64_SP"+$" },
  { "Cache-Control", "^("QS_H_CACHE"){1}(,[ ]?"QS_H_CACHE")*$" },
  { "Connection", "^[a-zA-Z0-9\\-]+$" },
  { "Content-Encoding", "^[a-zA-Z0-9\\-]+$" },
  { "Content-Language", "^[a-zA-Z0-9\\-]+$" },
  { "Content-Length", "^[0-9]+$" },
  { "Content-Location", "^"QS_URL"+$" },
  { "Content-md5", "^"QS_B64_SP"$" },
  { "Content-Range", "^.*$" },
  { "Content-Type", "^("QS_H_CONTENT"){1}(,[ ]?"QS_H_CONTENT")*$" },
  { "Cookie", "^"QS_H_COOKIE"+$" },
  { "Cookie2", "^"QS_H_COOKIE"+$" },
  { "Expect", "^"QS_H_EXPECT"+$" },
  { "From", "^"QS_H_FROM"+$" },
  { "Host", "^"QS_H_HOST"+$" },
  { "If-Match", "^"QS_H_IFMATCH"+$" },
  { "If-Modified-Since", "^"QS_H_DATE"+$" },
  { "If-None-Match", "^"QS_H_IFMATCH"+$" },
  { "If-Range", "^"QS_H_IFMATCH"+$" },
  { "If-Unmodified-Since", "^"QS_H_DATE"+$" },
  { "Keep-Alive", "^[0-9]+$" },
  { "Max-Forwards", "^[0-9]+$" },
  { "Proxy-Authorization", "^"QS_B64_SP"$" },
  { "Pragma", "^"QS_H_PRAGMA"+$" },
  { "Range", "^"QS_URL"+$" },
  { "Referer", "^"QS_URL"+$" },
  { "TE", "^("QS_H_TE"){1}(,[ ]?"QS_H_TE")*$" },
  { "User-Agent", "^[a-zA-Z0-9\\-_\\.:;\\(\\) /\\+!]+$" },
  { "Via", "^[a-zA-Z0-9\\-_\\.:;\\(\\) /\\+!]+$" },
  { "X-Forwarded-For", "^[a-zA-Z0-9\\-_\\.:]+$" },
  { "X-Forwarded-Host", "^[a-zA-Z0-9\\-_\\.:]+$" },
  { "X-Forwarded-Server", "^[a-zA-Z0-9\\-_\\.:]+$" },
  { "X-lori-time-1", "^[0-9]+$" },
  { NULL, NULL }
};

/* loads the default header rules into the server configuration */
static char *qos_load_headerfilter(apr_pool_t *pool, apr_table_t *hfilter_table) {
  const char *errptr = NULL;
  int erroffset;
  const qos_hel_t* elt;
  for(elt = qs_header_rules; elt->name != NULL ; ++elt) {
    pcre *p = pcre_compile(elt->pcre, PCRE_DOTALL, &errptr, &erroffset, NULL);
    if(p == NULL) {
      return apr_psprintf(pool, "could not compile pcre %s at position %d,"
                          " reason: %s", 
                          elt->name,
                          erroffset, errptr);
    }
    apr_table_setn(hfilter_table, elt->name, (char *)p);
    apr_pool_cleanup_register(pool, p, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  }
  return NULL;
}

/* returns the request id from mod_unique_id (if available) */
static const char *qos_unique_id(request_rec *r, const char *eid) {
  const char *uid = apr_table_get(r->subprocess_env, "UNIQUE_ID");
  apr_table_set(r->notes, "error-notes", eid);
  if(uid == NULL) {
    return apr_pstrdup(r->pool, "-");
  }
  return uid;
}

static char *qos_revision(apr_pool_t *p) {
  char *ver = apr_pstrdup(p, &revision[strlen("$Id: mod_qos.c,v ")]);
  char *h = strchr(ver, ' ');
  h[0] = '\0';
  return ver;
}

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
                    QOS_LOG_PFX(020)"session cookie verification failed, "
                    "invalid base64 encoding, id=%s", qos_unique_id(r, "020"));
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
                      QOS_LOG_PFX(021)"session cookie verification failed, "
                      "invalid size, id=%s", qos_unique_id(r, "021"));
        return 0;
      } else {
        qos_session_t *s = (qos_session_t *)buf;
        s->magic[QOS_MAGIC_LEN] = '\0';
        if(strcmp(qs_magic, s->magic) != 0) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                        QOS_LOG_PFX(022)"session cookie verification failed, "
                        "invalid magic, id=%s", qos_unique_id(r, "022"));
          return 0;
        }
        if(s->time < time(NULL) - sconf->max_age) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                        QOS_LOG_PFX(023)"session cookie verification failed, "
                        "expired, id=%s", qos_unique_id(r, "023"));
          return 0;
        }
      }
    }

    /* success */
    return 1;
  
  failed:
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX(024)"session cookie verification failed, "
                  "could not decrypt data, id=%s", qos_unique_id(r, "024"));
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
                QOS_LOG_PFX(025)"failed to create session cookie, id=%s",
                qos_unique_id(r, "025"));
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
  ap_log_error(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, NULL,
               QOS_LOG_PFX(001)"cleanup shared memory: %d bytes",
               act->size);
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
  u->act_table = apr_table_make(ppool, 2);
  apr_pool_userdata_set(u, QS_USR_SPE, apr_pool_cleanup_null, ppool);
  return u;
}

/**
 * tells if server is terminating immediately or not
 */
static int qos_is_graceful(qs_actable_t *act) {
  qos_user_t *u = qos_get_user_conf(act->ppool);
  if(ap_my_generation != act->generation) return 1;
  return 0;
}

/**
 * destroys the act
 * shared memory must not be destroyed before graceful restart has
 * been finished due running requests still need the shared memory
 * till they have finished.
 * keep the memory leak as little as possible ...
 */
static apr_status_t qos_cleanup_shm(void *p) {
  qs_actable_t *act = p;
  qos_user_t *u = qos_get_user_conf(act->ppool);
  /* this_generation id is never deleted ... */
  char *this_generation = apr_psprintf(act->ppool, "%d", ap_my_generation);
  char *last_generation;
  int i;
  apr_table_entry_t *entry;
  if(qos_is_graceful(act)) {
    last_generation = apr_psprintf(act->pool, "%d", ap_my_generation-1);
  } else {
    last_generation = this_generation;
  }
  /* delete acts from the last graceful restart */
  entry = (apr_table_entry_t *)apr_table_elts(u->act_table)->elts;
  for(i = 0; i < apr_table_elts(u->act_table)->nelts; i++) {
    if(strcmp(entry[i].key, last_generation) == 0) {
      qs_actable_t *a = (qs_actable_t *)entry[i].val;
      qos_destroy_act(a);
    }
  }
  apr_table_unset(u->act_table, last_generation);
  if(qos_is_graceful(act)) {
    /* don't delete this act now, but at next server restart ... */
    apr_table_addn(u->act_table, this_generation, (char *)act);
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
               QOS_LOG_PFX(002)"%s(%s), create shared memory: %d bytes (r=%d,ip=%d)", 
               s->server_hostname == NULL ? "-" : s->server_hostname,
               s->is_virtual ? "v" : "b", act->size, rule_entries, max_ip);
  res = apr_shm_create(&act->m, (act->size + 512), act->m_file, act->pool);
  if (res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                 QOS_LOG_PFX(003)"could not create shared memory: %s", buf);
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
    if(e->limit == 0) {
      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, s,
                   QOS_LOG_PFX(004)"request level rule %s has no limitation",
                   e->url);
    }
    e->interval = time(NULL);
    e->req_per_sec_limit = rule->req_per_sec_limit;
    e->kbytes_per_sec_limit = rule->kbytes_per_sec_limit;
    e->counter = 0;
    e->lock_file = apr_psprintf(act->pool, "%s_e%d.mod_qos", 
                                ap_server_root_relative(act->pool, tmpnam(NULL)), i);
    res = apr_global_mutex_create(&e->lock, e->lock_file, APR_LOCK_DEFAULT, act->pool);
    if (res != APR_SUCCESS) {
      char buf[MAX_STRING_LEN];
      apr_strerror(res, buf, sizeof(buf));
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                   QOS_LOG_PFX(005)"could create mutex: %s", buf);
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

static void qos_print_ip(request_rec *r, qs_ip_entry_t *ipe) {
  if(ipe) {
    unsigned long ip = ipe->ip;
    int a,b,c,d;
    a = ip % 256;
    ip = ip / 256;
    b = ip % 256;
    ip = ip / 256;
    c = ip % 256;
    ip = ip / 256;
    d = ip % 256;
    ap_rputs("<tr class=\"row1\">", r);
    ap_rputs("<td style=\"width:85%\">", r);
    ap_rprintf(r, "%d.%d.%d.%d</td><td>%d</td></tr>\n", a,b,c,d, ipe->counter);
    qos_print_ip(r, ipe->left);
    qos_print_ip(r, ipe->right);
  }
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
#ifdef QS_INTERNAL_TEST
  /* use one of the predefined ip addresses */
  if(cconf->sconf->enable_testip) {
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
      if(e->url && (strncmp(e->url, r->parsed_uri.path, e->url_len) == 0)) {
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
  if(r->subprocess_env) {
    const char *v = apr_table_get(r->subprocess_env, "QS_VipRequest");
    if(v && (strcasecmp(v, "yes") == 0)) {
      return 1;
    }
  }
  return 0;
}

int qos_hex2c(const char *x) {
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

/* url escaping (%xx) */
static int qos_unescaping(char *x) {
  int i, j, ch;
  if (x[0] == '\0')
    return 0;
  for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
    ch = x[i];
    if (ch == '%' && isxdigit(x[i + 1]) && isxdigit(x[i + 2])) {
      ch = qos_hex2c(&x[i + 1]);
      i += 2;
    }
    x[j] = ch;
  }
  x[j] = '\0';
  return j;
}

static int qos_per_dir_rules(request_rec *r, qos_dir_config *dconf) {
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(dconf->rfilter_table)->elts;
  int i;
  char *path = apr_pstrdup(r->pool, r->parsed_uri.path);
  char *query = NULL;
  char *fragment = NULL;
  char *request_line = apr_pstrdup(r->pool, r->the_request);
  char *uri = path;
  int request_line_len;
  int path_len;
  int query_len = 0;
  int fragment_len = 0;
  int uri_len;
  int permit_rule = 0;
  int permit_rule_match = 0;
  int permit_rule_action = QS_DENY;
  qos_unescaping(request_line);
  request_line_len = strlen(request_line);
  qos_unescaping(path);
  path_len = strlen(path);
  uri_len = path_len;
  if(r->parsed_uri.query) {
    query = apr_pstrdup(r->pool, r->parsed_uri.query);
    qos_unescaping(query);
    query_len = strlen(query);
    uri = apr_pstrcat(r->pool, path, "?", query, NULL);
    uri_len = strlen(uri);
  }
  if(r->parsed_uri.fragment) {
    fragment = apr_pstrdup(r->pool, r->parsed_uri.fragment);
    qos_unescaping(fragment);
    fragment_len = strlen(fragment);
    uri = apr_pstrcat(r->pool, uri, "#", fragment, NULL);
    uri_len = strlen(uri);
  }

  for(i = 0; i < apr_table_elts(dconf->rfilter_table)->nelts; i++) {
    if(entry[i].key[0] == '+') {
      int deny_rule = 0;
      int ex = -1;
      qos_rfilter_t *rfilter = (qos_rfilter_t *)entry[i].val;
      if(rfilter->type == QS_DENY_REQUEST_LINE) {
        deny_rule = 1;
        ex = pcre_exec(rfilter->pr, NULL, request_line, request_line_len, 0, 0, NULL, 0);
      } else if(rfilter->type == QS_DENY_PATH) {
        deny_rule = 1;
        ex = pcre_exec(rfilter->pr, NULL, path, path_len, 0, 0, NULL, 0);
      } else if(rfilter->type == QS_DENY_QUERY) {
        deny_rule = 1;
        ex = pcre_exec(rfilter->pr, NULL, query, query_len, 0, 0, NULL, 0);
      } else {
        permit_rule = 1;
        ex = pcre_exec(rfilter->pr, NULL, uri, uri_len, 0, 0, NULL, 0);
        permit_rule_action = rfilter->action;
        if(ex == 0) {
          permit_rule_match = 1; 
        }
      }
      if(deny_rule && (ex == 0)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOS_LOG_PFX(040)"access denied, rule id: %s (%s), action=%s, c=%s, id=%s",
                      rfilter->id,
                      rfilter->text, rfilter->action == QS_DENY ? "deny" : "log only",
                      r->connection->remote_ip == NULL ? "-" : r->connection->remote_ip,
                      qos_unique_id(r, "040"));
        if(rfilter->action == QS_DENY) {
          return HTTP_FORBIDDEN;
        }
      }
    }
  }
  if(permit_rule && !permit_rule_match) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(041)"access denied, no permit rule match, action=%s, c=%s, id=%s",
                  permit_rule_action == QS_DENY ? "deny" : "log only",
                  r->connection->remote_ip == NULL ? "-" : r->connection->remote_ip,
                  qos_unique_id(r, "041"));
    if(permit_rule_action == QS_DENY) {
      return HTTP_FORBIDDEN;
    }
  }
  return APR_SUCCESS;
}

static void qos_header_filter(request_rec *r, qos_srv_config *sconf) {
  apr_table_t *delete = apr_table_make(r->pool, 1);
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(r->headers_in)->elts;
  for(i = 0; i < apr_table_elts(r->headers_in)->nelts; i++) {
    pcre *p = (pcre *)apr_table_get(sconf->hfilter_table, entry[i].key);
    if(p) {
      if(pcre_exec(p, NULL, entry[i].val, strlen(entry[i].val), 0, 0, NULL, 0) < 0) {
        apr_table_add(delete, entry[i].key, entry[i].val);
      }
    } else {
      apr_table_add(delete, entry[i].key, entry[i].val);
    }
  }
  entry = (apr_table_entry_t *)apr_table_elts(delete)->elts;
  for(i = 0; i < apr_table_elts(delete)->nelts; i++) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX(042)"drop header \'%s: %s\', c=%s, id=%s",
                  entry[i].key, entry[i].val,
                  r->connection->remote_ip == NULL ? "-" : r->connection->remote_ip,
                  qos_unique_id(r, "042"));
    apr_table_unset(r->headers_in, entry[i].key);
  }
}

/************************************************************************
 * "public"
 ***********************************************************************/
static int qos_ext_status_hook(request_rec *r, int flags) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  server_rec *s = sconf->base_server;
  int i = 0;
  time_t now = time(NULL);
  if (flags & AP_STATUS_SHORT)
    return OK;

  ap_rprintf(r, "<h2>mod_qos %s</h2>\n", qos_revision(r->pool));
  if(strcmp(r->handler, "qos-viewer") == 0) {
    ap_rputs("<table class=\"btable\">\n", r);
  } else {
    ap_rputs("<hr>\n", r);
    ap_rputs("<table border=\"1\">\n", r);
  }
  
  while(s) {
    qs_acentry_t *e;
    ap_rputs("<tr class=\"rows\">\n", r);
    ap_rprintf(r, "<td style=\"vertical-align: top;\">%s:%d <br> (%s)</td>\n",
               s->server_hostname == NULL ? "-" : s->server_hostname,
               s->addrs->host_port,
               s->is_virtual ? "virtual" : "base");
    ap_rputs("<td>\n", r);
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    if(sconf && sconf->act) {
      e = sconf->act->entry;
      while(e) {
        int percent = e->counter * 100 / (e->limit == 0 ? 1 : e->limit);
        int cr = 255;
        int cg = 255;
        int cb = 255;
        if(percent > 70) {
          cr = 255;
          cg = 255;
          cb = 90;
        }
        if(percent > 95) {
          cr = 255;
          cg = 0;
          cb = 0;
        }
        if(strcmp(r->handler, "qos-viewer") == 0) {
          ap_rputs("<table class=\"btable\">\n", r);
        } else {
          ap_rputs("<table border=\"1\">\n", r);
        }
        ap_rprintf(r, "<tr class=\"rowt\">"
                   "<td style=\"width:70%\">rule:&nbsp;%s&nbsp;</td>"
                   "<td style=\"width:15%\">limit&nbsp;</td>"
                   "<td style=\"width:15%\">current&nbsp;</td>"
                   "</tr>\n", e->url);
        ap_rprintf(r, "<!-- %d --><tr class=\"row1\">", i);
        ap_rprintf(r, "<td>concurrent requests</td>");
        ap_rprintf(r, "<td>%d</td>", e->limit == 0 ? -1 : e->limit);
        ap_rprintf(r, "<td style=\"background-color: rgb(%d, %d, %d);\">%d</td>",
                   cr, cg, cb,
                   e->counter);
        ap_rputs("</tr>\n", r);
        if(e->req_per_sec_block_rate) {
          cr = 255;
          cg = 255;
          cb = 90;
        } else {
          cr = 255;
          cg = 255;
          cb = 255;
        }
        ap_rprintf(r, "<!-- %d --><tr class=\"row1\">", i);
        ap_rprintf(r, "<td>requests/second (wait rate %dms)</td>",
                   e->req_per_sec_block_rate);
        ap_rprintf(r, "<td>%ld</td>",
                   e->req_per_sec_limit == 0 ? -1 : e->req_per_sec_limit);
        ap_rprintf(r, "<td style=\"background-color: rgb(%d, %d, %d);\">%ld</td>",
                   cr, cg, cb,
                   now > (e->interval + 11) ? 0 : e->req_per_sec);
        ap_rputs("</tr>\n", r);
        if(e->kbytes_per_sec_block_rate) {
          cr = 255;
          cg = 255;
          cb = 90;
        } else {
          cr = 255;
          cg = 255;
          cb = 255;
        }
        ap_rprintf(r, "<td>kbytes/second (wait rate %dms)</td>",
                   e->kbytes_per_sec_block_rate);
        ap_rprintf(r, "<td>%ld</td>",
                   e->kbytes_per_sec_limit == 0 ? -1 : e->kbytes_per_sec_limit);
        ap_rprintf(r, "<td style=\"background-color: rgb(%d, %d, %d);\">%ld</td>",
                   cr, cg, cb,
                   now > (e->interval + 11) ? 0 : e->kbytes_per_sec);
        ap_rputs("</tr>\n", r);
        e = e->next;
        ap_rputs("</table>\n", r);
      }
    }
    if(sconf) {
      qs_ip_entry_t *f;
      int c = 0;
      int cr = 255;
      int cg = 255;
      int cb = 255;
      if((sconf->max_conn_close > 0) &&
         (sconf->act->c->connections >= sconf->max_conn_close)) {
        cr = 255;
        cg = 255;
        cb = 90;
      }
      if((sconf->max_conn > 0) &&
         (sconf->act->c->connections >= sconf->max_conn)) {
        cr = 255;
        cg = 0;
        cb = 0;
      }
      apr_global_mutex_lock(sconf->act->lock);   /* @CRT7 */
      f = sconf->act->c->ip_free;
      while(f) {
        c++;
        f = f->next;
      }
      apr_global_mutex_unlock(sconf->act->lock); /* @CRT7 */
      if(strcmp(r->handler, "qos-viewer") == 0) {
        ap_rputs("<table class=\"btable\">\n", r);
      } else {
        ap_rputs("<table border=\"1\">\n", r);
      }
      ap_rputs("<tr class=\"rowt\">"
               "<td style=\"width:85%\">connections</td>"
               "<td>current&nbsp;</td></tr>\n", r);
      ap_rputs("<tr class=\"row1\">\n", r);
      ap_rputs("<td style=\"width:85%\">\n", r);
      ap_rprintf(r,"<!-- %d -->free ip entries</td><td>%d</td>\n", i, c);
      ap_rputs("</tr>", r);
      ap_rputs("<tr class=\"row1\">\n", r);
      ap_rputs("<td style=\"width:85%\">\n", r);
      ap_rprintf(r,"<!-- %d -->current connections</td>"
                 "<td style=\"background-color: rgb(%d, %d, %d);\">%d</td>\n",
                 i, cr, cg, cb, sconf->act->c->connections);
      ap_rputs("</tr>", r);
      ap_rputs("</table>\n", r);

      if(r->parsed_uri.query && strstr(r->parsed_uri.query, "ip")) {
        if(strcmp(r->handler, "qos-viewer") == 0) {
          ap_rputs("<table class=\"btable\">\n", r);
        } else {
          ap_rputs("<table border=\"1\">\n", r);
        }
        ap_rputs("<tr class=\"rowt\">"
                 "<td style=\"width:85%\">client ip connections</td>"
                 "<td>current&nbsp;</td></tr>", r);
        apr_global_mutex_lock(sconf->act->lock);   /* @CRT8 */
        qos_print_ip(r, sconf->act->c->ip_tree);
        apr_global_mutex_unlock(sconf->act->lock); /* @CRT8 */
        ap_rputs("</table>\n", r);
      }

      if(strcmp(r->handler, "qos-viewer") == 0) {
        ap_rputs("<table class=\"btable\">\n", r);
      } else {
        ap_rputs("<table border=\"1\">\n", r);
      }
      ap_rputs("<tr class=\"rowt\">"
               "<td style=\"width:85%\">settings</td>"
               "<td>limit&nbsp;</td></tr>\n", r);
      ap_rputs("<tr class=\"row1\">\n", r);
      ap_rputs("<td style=\"width:85%\">\n", r);
      ap_rprintf(r,"max connections</td><td>%d</td>\n", sconf->max_conn);
      ap_rputs("</tr>", r);
      ap_rputs("<tr class=\"row1\">\n", r);
      ap_rputs("<td style=\"width:85%\">\n", r);
      ap_rprintf(r,"max connections with keep-alive</td><td>%d</td>\n", sconf->max_conn_close);
      ap_rputs("</tr>", r);
      ap_rputs("<tr class=\"row1\">\n", r);
      ap_rputs("<td style=\"width:85%\">\n", r);
      ap_rprintf(r,"max connections per client</td><td>%d</td>\n", sconf->max_conn_per_ip);
      ap_rputs("</tr>", r);
      ap_rputs("<tr class=\"row1\">\n", r);
      ap_rputs("<td style=\"width:85%\">\n", r);
      ap_rprintf(r,"inital connection timeout</td><td>%d</td>\n", sconf->connect_timeout);
      ap_rputs("</tr>", r);
      ap_rputs("</table>\n", r);
    }
    i++;
    s = s->next;
    ap_rputs("</td></tr>\n", r);

  }

  ap_rputs("</table>\n", r);

  ap_rputs("<hr>\n", r);
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

    /* control timeout */
    if(sconf && (sconf->connect_timeout != -1)) {
      ap_filter_t *f = c->input_filters;
      while(f) {
        if(strcmp(f->frec->name, "qos-in-filter") == 0) {
          qos_ifctx_t *inctx = f->ctx;
          if(inctx->status == QS_CONN_STATE_NEW) {
            apr_status_t rv = apr_socket_timeout_get(inctx->client_socket, &inctx->at);
            if(rv == APR_SUCCESS) {
              server_rec *sc;
              /* set short timeout */
              apr_socket_timeout_set(inctx->client_socket, inctx->qt);
              inctx->status = QS_CONN_STATE_SHORT;
              /* make change "persisten" till we got the whole request
                 line and headers (again, ugly but it works) */
              inctx->server_timeout = c->base_server->timeout;
              sc = apr_pcalloc(c->pool, sizeof(server_rec));
              memcpy(sc, c->base_server, sizeof(server_rec));
              c->base_server = sc;
              c->base_server->timeout = inctx->qt;
            }
          }
          break;
        }
      }
    }

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
        if(entry[i].val[0] == 'r') {
          if(strncmp(entry[i].key, cconf->c->remote_ip, strlen(entry[i].key)) == 0) {
            vip = 1;
            cconf->evmsg = apr_pstrcat(c->pool, "S;", cconf->evmsg, NULL);
          }
        } else {
          if(strcmp(entry[i].key, cconf->c->remote_ip) == 0) {
            vip = 1;
            cconf->evmsg = apr_pstrcat(c->pool, "S;", cconf->evmsg, NULL);
          }
        }
      }
    }

    /* enforce rules */
    if((sconf->max_conn != -1) && !vip) {
      if(connections > sconf->max_conn) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                     QOS_LOG_PFX(030)"access denied, rule: max=%d, concurrent connections=%d, "
                     "c=%s",
                     sconf->max_conn, connections,
                     c->remote_ip == NULL ? "-" : c->remote_ip);
        c->keepalive = AP_CONN_CLOSE;
        return qos_return_error(c);
      }
    }
    if((sconf->max_conn_per_ip != -1) && !vip) {
      if(current > sconf->max_conn_per_ip) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                     QOS_LOG_PFX(031)"access denied, rule: max_ip=%d, concurrent connections=%d, "
                     "c=%s",
                     sconf->max_conn_per_ip, current,
                     c->remote_ip == NULL ? "-" : c->remote_ip);
        c->keepalive = AP_CONN_CLOSE;
        return qos_return_error(c);
      }
    }
  }
  return DECLINED;
}

static int qos_pre_connection(conn_rec * c, void *skt) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(c->base_server->module_config,
                                                                &qos_module);
  qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(c->conn_config, &qos_module);
  if(sconf && (sconf->connect_timeout != -1)) {
    qos_ifctx_t *inctx = apr_pcalloc(c->pool, sizeof(qos_ifctx_t));
    inctx->client_socket = skt;
    inctx->status = QS_CONN_STATE_NEW;
    inctx->qt = apr_time_from_sec(sconf->connect_timeout);
    ap_add_input_filter("qos-in-filter", inctx, NULL, c);
  }
  return DECLINED;
}

static int qos_post_read_request(request_rec * r) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->connection->base_server->module_config,
                                                                &qos_module);
  if(sconf && (sconf->connect_timeout != -1)) {
    ap_filter_t *f = r->connection->input_filters;
    while(f) {
      if(strcmp(f->frec->name, "qos-in-filter") == 0) {
        qos_ifctx_t *inctx = f->ctx;
        if(inctx->status == QS_CONN_STATE_SHORT) {
          /* clear short timeout */
          apr_socket_timeout_set(inctx->client_socket, inctx->at);
          inctx->status = QS_CONN_STATE_END;
          r->connection->base_server->timeout = inctx->server_timeout;
        }
        break;
      }
      f = f->next;
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
    qs_acentry_t *e;
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_module);
    qos_dir_config *dconf = (qos_dir_config*)ap_get_module_config(r->per_dir_config,
                                                                  &qos_module);
    if(apr_table_elts(dconf->rfilter_table)->nelts > 0) {
      apr_status_t rv = qos_per_dir_rules(r, dconf);
      if(rv != APR_SUCCESS) {
        const char *error_page = sconf->error_page;
        qs_req_ctx *rctx = qos_rctx_config_get(r);
        if(r->subprocess_env) {
          const char *v = apr_table_get(r->subprocess_env, "QS_ErrorPage");
          if(v) {
            error_page = v;
          }
        }
        rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
        if(error_page) {
          qos_error_response(r, error_page);
          return DONE;
        }
        return rv;
      }
    }
    if(dconf->headerfilter > 0) {
      qos_header_filter(r, sconf);
    }

    /* set dynamic keep alive */
    if(r->subprocess_env) {
      const char *v = apr_table_get(r->subprocess_env, "QS_KeepAliveTimeout");
      if(v) {
        int ka = atoi(v);
        if(ka > 0) {
          /* well, at least it works ... */
          qs_req_ctx *rctx = qos_rctx_config_get(r);
          apr_interval_time_t kat = apr_time_from_sec(ka);
          server_rec *sr = apr_pcalloc(r->connection->pool, sizeof(server_rec));
          server_rec *sc = apr_pcalloc(r->connection->pool, sizeof(server_rec));
          rctx->evmsg = apr_pstrcat(r->pool, "T;", rctx->evmsg, NULL);
          memcpy(sr, r->server, sizeof(server_rec));
          memcpy(sc, r->connection->base_server, sizeof(server_rec));
          r->server = sr;
          r->server->keep_alive_timeout = kat;
          r->connection->base_server = sc;
          r->connection->base_server->keep_alive_timeout = kat;
        }
      }
    }
    
    /* 1st prio has "Match" rule */
    e = qos_getrule_byregex(r, sconf);
    /* 2th prio has "URL" rule */
    if(!e) e = qos_getrule_bylocation(r, sconf);
    if(e) {
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      int req_per_sec_block = 0;
      const char *error_page = sconf->error_page;
      if(r->subprocess_env) {
        const char *v = apr_table_get(r->subprocess_env, "QS_ErrorPage");
        if(v) {
          error_page = v;
        }
      }
      if(sconf->header_name) {
        rctx->is_vip = qos_is_vip(r, sconf);
      }
      rctx->entry = e;
      apr_global_mutex_lock(e->lock);   /* @CRT5 */
      e->counter++;
      req_per_sec_block = e->req_per_sec_block_rate;
      apr_global_mutex_unlock(e->lock); /* @CRT5 */
      
      /*
       * QS_LocRequestLimitMatch/QS_LocRequestLimit/QS_LocRequestLimitDefault enforcement
       */
      if(e->limit && (e->counter > e->limit)) {
        /* vip session has no limitation */
        if(rctx->is_vip) {
          rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
        } else {
          /* std user */
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        QOS_LOG_PFX(010)"access denied, rule: %s(%d), concurrent requests=%d, "
                        "c=%s, id=%s",
                        e->url, e->limit, e->counter,
                        r->connection->remote_ip == NULL ? "-" : r->connection->remote_ip,
                        qos_unique_id(r, "010"));
          rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
          if(error_page) {
            qos_error_response(r, error_page);
            return DONE;
          }
          return HTTP_INTERNAL_SERVER_ERROR;
        }
      }
      /*
       * QS_LocRequestPerSecLimit enforcement
       */
      if(req_per_sec_block) {
        if(rctx->is_vip) {
          rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
        } else {
          int sec = req_per_sec_block / 1000;
          int nsec = req_per_sec_block % 1000;
          struct timespec delay;
          rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
          delay.tv_sec  = sec;
          delay.tv_nsec = nsec * 1000000;
          nanosleep(&delay,NULL);
        }
      }
      /*
       * QS_LocKBytesPerSecLimit enforcement
       */
      if(e->kbytes_per_sec_block_rate) {
        if(rctx->is_vip) {
          rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
        } else {
          rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
          ap_add_output_filter("qos-out-filter-delay", NULL, r, r->connection);
        }
      }
    }
  }
  return DECLINED;
}

/**
 * input filter, used to log timeout event
 */
static apr_status_t qos_in_filter(ap_filter_t * f, apr_bucket_brigade * bb,
                                  ap_input_mode_t mode, apr_read_type_e block,
                                  apr_off_t nbytes) {
  apr_status_t rv = ap_get_brigade(f->next, bb, mode, block, nbytes);
  qos_ifctx_t *inctx = f->ctx;
  if((rv == APR_TIMEUP) && (inctx->status == QS_CONN_STATE_SHORT)) {
    int qti = apr_time_sec(inctx->qt);
    f->c->base_server->timeout = inctx->server_timeout;
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, f->c->base_server,
                 QOS_LOG_PFX(032)"connection timeout, rule: %d sec inital timeout, c=%s",
                 qti,
                 f->c->remote_ip == NULL ? "-" : f->c->remote_ip);
  }
  return rv;
}

static apr_status_t qos_out_filter_delay(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  if(rctx->entry) {
    /*
     * QS_LocKBytesPerSecLimit enforcement
     */
    int kbytes_per_sec_block = rctx->entry->kbytes_per_sec_block_rate;
    int sec = kbytes_per_sec_block / 1000;
    int nsec = kbytes_per_sec_block % 1000;
    struct timespec delay;
    delay.tv_sec  = sec;
    delay.tv_nsec = nsec * 1000000;
    nanosleep(&delay,NULL);
  }
  return ap_pass_brigade(f->next, bb); 
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
 * "free resources" and update stats
 */
static int qos_logger(request_rec *r) {
  const char *uid;
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  qs_acentry_t *e = rctx->entry;
  qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config, &qos_module);
  if(cconf && cconf->evmsg) {
    rctx->evmsg = apr_pstrcat(r->pool, cconf->evmsg, rctx->evmsg, NULL);
  }
  if(e) {
    time_t now = time(NULL);
    char *h = apr_psprintf(r->pool, "%d", e->counter);
    apr_global_mutex_lock(e->lock);   /* @CRT6 */
    e->counter--;
    e->req++;
    e->bytes = e->bytes + r->bytes_sent;
    if(now > e->interval + 10) {
      e->req_per_sec = e->req / (now - e->interval);
      e->req = 0;
      e->kbytes_per_sec = e->bytes / (now - e->interval) / 1024;
      e->bytes = 0;
      e->interval = now;
      if(e->req_per_sec_limit) {
        if(e->req_per_sec > e->req_per_sec_limit) {
          int factor = ((e->req_per_sec * 100) / e->req_per_sec_limit) - 100;
          e->req_per_sec_block_rate = e->req_per_sec_block_rate + factor;
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                        QOS_LOG_PFX(050)"request rate limit, rule: %s(%ld), req/sec=%ld,"
                        " delay=%ldms",
                        e->url, e->req_per_sec_limit,
                        e->req_per_sec, e->req_per_sec_block_rate);
        } else if(e->req_per_sec_block_rate > 0) {
          if(e->req_per_sec_block_rate < 50) {
            e->req_per_sec_block_rate = 0;
          } else {
            int factor = e->req_per_sec_block_rate / 10;
            e->req_per_sec_block_rate = e->req_per_sec_block_rate - factor;
          }
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                        QOS_LOG_PFX(051)"request rate limit, rule: %s(%ld), req/sec=%ld,"
                        " delay=%dms",
                        e->url, e->req_per_sec_limit,
                        e->req_per_sec, e->req_per_sec_block_rate);
        }
      }
      if(e->kbytes_per_sec_limit) {
        if(e->kbytes_per_sec > e->kbytes_per_sec_limit) {
          int factor = ((e->kbytes_per_sec * 100) / e->kbytes_per_sec_limit) - 100;
          e->kbytes_per_sec_block_rate = e->kbytes_per_sec_block_rate + factor;
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                        QOS_LOG_PFX(052)"byte rate limit, rule: %s(%ld), kbytes/sec=%ld,"
                        " delay=%ldms",
                        e->url, e->kbytes_per_sec_limit,
                        e->kbytes_per_sec, e->kbytes_per_sec_block_rate);
        } else if(e->kbytes_per_sec_block_rate > 0) {
          if(e->kbytes_per_sec_block_rate < 50) {
            e->kbytes_per_sec_block_rate = 0;
          } else {
            int factor = e->kbytes_per_sec_block_rate / 10;
            e->kbytes_per_sec_block_rate = e->kbytes_per_sec_block_rate - factor;
          }
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                        QOS_LOG_PFX(053)"byte rate limit, rule: %s(%ld), kbytes/sec=%ld,"
                        " delay=%dms",
                        e->url, e->kbytes_per_sec_limit,
                        e->kbytes_per_sec, e->kbytes_per_sec_block_rate);
        }
      }
    }
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
  if(cconf && (cconf->sconf->max_conn != -1)) {
    char *cc = apr_psprintf(r->pool, "%d", cconf->sconf->act->c->connections);
    apr_table_set(r->headers_out, "mod_qos_con", cc);
    apr_table_set(r->err_headers_out, "mod_qos_con", cc);
    if(r->next) {
      apr_table_set(r->next->headers_out, "mod_qos_con", cc);
      apr_table_set(r->next->err_headers_out, "mod_qos_con", cc);
    }
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
  char *rev = qos_revision(ptemp);
  server_rec *s = bs->next;
  int rules = 0;
  qos_user_t *u = qos_get_user_conf(s->process->pool);
  u->server_start++;
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
  {
    char *vs = apr_psprintf(pconf, "mod_qos/%s", rev);
    ap_add_version_component(pconf, vs);
  }
               
#ifdef QS_INTERNAL_TEST
  fprintf(stdout, "\033[1mmod_qos TEST BINARY, NOT FOR PRODUCTIVE USE\033[0m\n");
  fflush(stdout);
#endif
  APR_OPTIONAL_HOOK(ap, status_hook, qos_ext_status_hook, NULL, NULL, APR_HOOK_MIDDLE);

  return DECLINED;
}

/**
 * to amuse ...
 */
static int qos_favicon(request_rec *r) {
  int i;
  unsigned const char ico[] = { 0x0,0x0,0x1,0x0,0x1,0x0,0x10,0x10,0x0,0x0,0x1,0x0,0x20,0x0,0x68,0x4,0x0,0x0,0x16,0x0,0x0,0x0,0x28,0x0,0x0,0x0,0x10,0x0,0x0,0x0,0x20,0x0,0x0,0x0,0x1,0x0,0x20,0x0,0x0,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xfa,0xfa,0xfb,0xfd,0xb1,0xb1,0xe9,0xfd,0x6a,0x6a,0xea,0xfd,0x47,0x47,0xea,0xfd,0x47,0x47,0xe9,0xfd,0x6a,0x6b,0xea,0xfd,0xb2,0xb2,0xea,0xfd,0xfb,0xfb,0xfb,0xfd,0xfe,0xfe,0xfe,0xfd,0xe9,0xe8,0xf9,0xfd,0xa0,0xb8,0xdc,0xfd,0xc0,0xdf,0xe8,0xfd,0xff,0xff,0xff,0xfd,0xfc,0xfc,0xfc,0xfd,0xf9,0xf9,0xf9,0xfd,0xc1,0xc1,0xee,0xfd,0x27,0x27,0xec,0xfd,0x0,0x0,0xfe,0xfd,0x0,0x0,0xfe,0xfd,0x0,0x0,0xf1,0xfd,0x0,0x0,0xf1,0xfd,0x0,0x0,0xfe,0xfd,0x0,0x0,0xfe,0xfd,0x2f,0x2c,0xe6,0xfd,0x7c,0x60,0xc1,0xfd,0x3e,0x10,0x8c,0xfd,0x95,0x9f,0xd6,0xfd,0xfc,0xfd,0xfe,0xfd,0xff,0xff,0xff,0xfd,0xfe,0xfe,0xfe,0xfd,0x68,0x6c,0xac,0xfd,0x6,0x6,0xbb,0xfd,0x0,0x0,0xf1,0xfd,0x0,0x0,0x7d,0xfd,0x22,0x22,0x43,0xfd,0x52,0x52,0x53,0xfd,0x52,0x52,0x53,0xfd,0x21,0x22,0x45,0xfd,0x1a,0xe,0xbb,0xfd,0x36,0x7,0x8c,0xfd,0x30,0x4,0x91,0xfd,0x56,0x54,0x96,0xfd,0xfe,0xfe,0xfe,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xcd,0xda,0xf0,0xfd,0x7,0x5a,0xf2,0xfd,0x0,0x4,0x8b,0xfd,0x1,0x1,0x18,0xfd,0x9e,0x9e,0x9e,0xfd,0xdb,0xdb,0xdb,0xfd,0xa0,0xa0,0xa0,0xfd,0xa1,0xa1,0xa1,0xfd,0x72,0x5b,0xac,0xfd,0x3c,0x6,0x67,0xfd,0x19,0x2,0xc9,0xfd,0x0,0xb,0x6a,0xfd,0x9,0xda,0xda,0xfd,0xd0,0xf0,0xf0,0xfd,0xff,0xff,0xff,0xfd,0xfe,0xfe,0xfe,0xfd,0x3c,0x80,0xea,0xfd,0x0,0x62,0xf7,0xfd,0x3,0x11,0x9d,0xfd,0x0,0x0,0x87,0xfd,0xe,0xe,0xe,0xfd,0x3,0x1d,0x2d,0xfd,0x0,0x77,0xc2,0xfd,0x0,0x76,0xc2,0xfd,0x0,0x19,0x89,0xfd,0x5,0x0,0xed,0xfd,0x0,0x0,0x64,0xfd,0x4,0x28,0x28,0xfd,0x0,0xf8,0xf8,0xfd,0x3f,0xea,0xea,0xfd,0xfe,0xfe,0xfe,0xfd,0xcf,0xda,0xec,0xfd,0x0,0x64,0xfc,0xfd,0x0,0x3a,0x92,0xfd,0x9b,0x9a,0xa1,0xfd,0x1a,0x19,0xf3,0xfd,0x0,0x0,0x82,0xfd,0x0,0x0,0x0,0xfd,0x0,0x1e,0x49,0xfd,0x0,0x1d,0xcc,0xfd,0x0,0x0,0xfd,0xfd,0x0,0x0,0x69,0xfd,0x1c,0x1c,0x1c,0xfd,0x99,0x99,0x98,0xfd,0x0,0x94,0x95,0xfd,0x0,0xfb,0xfb,0xfd,0xd2,0xed,0xed,0xfd,0x8c,0xb1,0xea,0xfd,0x0,0x65,0xff,0xfd,0x10,0x28,0x49,0xfd,0xe4,0xe4,0xe4,0xfd,0x7,0x22,0x7f,0xfd,0x0,0x0,0xfe,0xfd,0x0,0x0,0xb6,0xfd,0x0,0x0,0xfc,0xfd,0x0,0x0,0xfc,0xfd,0x0,0x0,0xaa,0xfd,0x0,0x0,0x0,0xfd,0x8,0x23,0x34,0xfd,0xe6,0xe6,0xe6,0xfd,0xe,0x49,0x4a,0xfd,0x0,0xff,0xff,0xfd,0x90,0xea,0xea,0xfd,0x6a,0x9c,0xea,0xfd,0x0,0x65,0xfe,0xfd,0x3b,0x41,0x4a,0xfd,0xb5,0xb5,0xb5,0xfd,0x0,0x6d,0xb4,0xfd,0x0,0x23,0xe0,0xfd,0x0,0x0,0xd6,0xfd,0x0,0x0,0xa6,0xfd,0x0,0x0,0xbf,0xfd,0x0,0x0,0xd5,0xfd,0x0,0x25,0x58,0xfd,0x0,0x6b,0xb1,0xfd,0xb8,0xb8,0xb8,0xfd,0x38,0x49,0x4a,0xfd,0x0,0xfe,0xfe,0xfd,0x6e,0xe9,0xe9,0xfd,0x6a,0x9c,0xea,0xfd,0x0,0x65,0xfe,0xfd,0x3c,0x42,0x4b,0xfd,0xb5,0xb5,0xb5,0xfd,0x0,0x6e,0xb5,0xfd,0x0,0x24,0x5a,0xfd,0x0,0x0,0xb9,0xfd,0x0,0x0,0x9f,0xfd,0x0,0x0,0x9f,0xfd,0x0,0x0,0xc9,0xfd,0x0,0x26,0xe0,0xfd,0x0,0x6b,0xb1,0xfd,0xb8,0xb8,0xb8,0xfd,0x39,0x49,0x4a,0xfd,0x0,0xfe,0xfe,0xfd,0x6d,0xe9,0xe9,0xfd,0x8a,0xaf,0xea,0xfd,0x0,0x65,0xff,0xfd,0x12,0x28,0x49,0xfd,0xe5,0xe5,0xe5,0xfd,0x7,0x23,0x34,0xfd,0x0,0x0,0x0,0xfd,0x0,0x0,0xad,0xfd,0x0,0x0,0xfc,0xfd,0x0,0x0,0xfc,0xfd,0x0,0x0,0xb8,0xfd,0x0,0x0,0xfe,0xfd,0x8,0x24,0x7d,0xfd,0xe7,0xe7,0xe7,0xfd,0x10,0x49,0x49,0xfd,0x0,0xff,0xff,0xfd,0x8e,0xea,0xea,0xfd,0xcc,0xd8,0xec,0xfd,0x0,0x64,0xfd,0xfd,0x0,0x38,0x8d,0xfd,0xa0,0xa0,0xa0,0xfd,0x1a,0x1a,0x1a,0xfd,0x0,0x0,0x6c,0xfd,0x0,0x0,0xfd,0xfd,0x0,0x1c,0xca,0xfd,0x0,0x1b,0x46,0xfd,0x0,0x0,0x0,0xfd,0x0,0x0,0x87,0xfd,0x1c,0x1c,0xf2,0xfd,0x9e,0x9e,0xa3,0xfd,0x0,0x8f,0x90,0xfd,0x0,0xfc,0xfc,0xfd,0xd0,0xec,0xec,0xfd,0xfe,0xfe,0xfe,0xfd,0x37,0x7d,0xeb,0xfd,0x0,0x61,0xf5,0xfd,0x4,0x11,0x24,0xfd,0x0,0x0,0x66,0xfd,0xd,0xd,0xf5,0xfd,0x2,0x1d,0x8e,0xfd,0x0,0x78,0xc5,0xfd,0x0,0x77,0xc3,0xfd,0x3,0x1c,0x2b,0xfd,0xd,0xd,0xd,0xfd,0x0,0x0,0x8d,0xfd,0x5,0x26,0x98,0xfd,0x0,0xf6,0xf6,0xfd,0x3a,0xea,0xea,0xfd,0xfe,0xfe,0xfe,0xfd,0xff,0xff,0xff,0xfd,0xc8,0xd7,0xef,0xfd,0x6,0x5a,0xda,0xfd,0x0,0x4,0x6b,0xfd,0x2,0x2,0xa4,0xfd,0xa6,0xa6,0xb8,0xfd,0xda,0xda,0xda,0xfd,0x9d,0x9e,0x9d,0xfd,0x9e,0x9e,0x9e,0xfd,0xdb,0xdb,0xdb,0xfd,0xa4,0xa4,0xa3,0xfd,0x2,0x2,0xe,0xfd,0x0,0xb,0x8f,0xfd,0x6,0xdb,0xf3,0xfd,0xcb,0xef,0xf0,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xfe,0xfe,0xfe,0xfd,0x65,0x6a,0xa1,0xfd,0x4,0x4,0xa6,0xfd,0x0,0x0,0x8f,0xfd,0x0,0x0,0x47,0xfd,0x2a,0x2a,0x39,0xfd,0x5b,0x5b,0x5b,0xfd,0x5b,0x5b,0x5b,0xfd,0x29,0x29,0x39,0xfd,0x0,0x0,0x47,0xfd,0x0,0x0,0x90,0xfd,0x4,0x4,0x72,0xfd,0x68,0x74,0xad,0xfd,0xfe,0xfe,0xfe,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xfc,0xfc,0xfc,0xfd,0xf8,0xf8,0xfa,0xfd,0xb9,0xb8,0xd8,0xfd,0x20,0x20,0x9c,0xfd,0x0,0x0,0x99,0xfd,0x0,0x0,0x98,0xfd,0x0,0x0,0x8c,0xfd,0x0,0x0,0x8d,0xfd,0x0,0x0,0x98,0xfd,0x0,0x0,0x99,0xfd,0x21,0x21,0x9c,0xfd,0xbb,0xbb,0xd9,0xfd,0xf8,0xf8,0xf8,0xfd,0xfc,0xfc,0xfc,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xf8,0xf7,0xf9,0xfd,0xa7,0xa7,0xcf,0xfd,0x60,0x60,0xb2,0xfd,0x3e,0x3e,0xa6,0xfd,0x3e,0x3e,0xa6,0xfd,0x60,0x60,0xb3,0xfd,0xa8,0xa8,0xcf,0xfd,0xf8,0xf8,0xf9,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0 };
  ap_set_content_type(r, "image/x-icon");
  for(i=0; i < sizeof(ico); i++) {
    ap_rputc(ico[i], r);
  }
  return OK;
}

/**
 * handler which may be used as an alternative to mod_status
 */
static int qos_handler(request_rec * r) {
  if (strcmp(r->handler, "qos-viewer") != 0) {
    return DECLINED;
  } 
  if(strstr(r->parsed_uri.path, "favicon.ico") != NULL) {
    return qos_favicon(r);
  }
  ap_set_content_type(r, "text/html");
  //  apr_table_set(r->headers_out,"Cache-Control","no-cache");
  if(!r->header_only) {
    ap_rputs("<html><head><title>mod_qos</title>\n", r);
    ap_rprintf(r,"<link rel=\"shortcut icon\" href=\"%s/favicon.ico\"/>\n", r->parsed_uri.path);
    ap_rputs("<meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n", r);
    ap_rputs("<meta name=\"author\" content=\"Pascal Buchbinder\">\n", r);
    ap_rputs("<meta http-equiv=\"Pragma\" content=\"no-cache\">\n", r);
    ap_rputs("<style TYPE=\"text/css\">\n", r);
    ap_rputs("<!--", r);
    ap_rputs("  body {\n\
	background-color: white;\n\
	color: black;\n\
	font-family: arial, helvetica, verdana, sans-serif;\n\
  }\n\
  .btable{\n\
	  background-color: white;\n\
	  border: 1px solid;\n\
	  padding: 0px;\n\
	  margin: 6px;\n\
	  width: 550px;\n\
	  font-weight: normal;\n\
	  border-collapse: collapse;\n\
  }\n\
  .rowt {\n\
	  background-color: rgb(230,233,235);\n\
	  border: 1px solid;\n\
	  font-weight: bold;\n\
	  padding: 0px;\n\
	  margin: 0px;\n\
  }\n\
  .rows {\n\
	  background-color: rgb(240,243,245);\n\
	  border: 1px solid;\n\
	  font-weight: bold;\n\
	  padding: 0px;\n\
	  margin: 0px;\n\
  }\n\
  .row1 {\n\
	  background-color: white;\n\
	  border: 1px solid;\n\
	  font-weight: normal;\n\
	  padding: 0px;\n\
	  margin: 0px;\n\
  }\n\
", r);
    ap_rputs("-->\n", r);
    ap_rputs("</style>\n", r);
    ap_rputs("</head><body>", r);
    qos_ext_status_hook(r, 0);
    ap_rputs("</body></html>", r);
  }
  return OK;
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

static void *qos_dir_config_create(apr_pool_t *p, char *d) {
  qos_dir_config *dconf = apr_pcalloc(p, sizeof(qos_rfilter_t));
  dconf->rfilter_table = apr_table_make(p, 1);
  dconf->inheritoff = 0;
  dconf->headerfilter = -1;
  return dconf;
}

/**
 * merges dir config
 */
static void *qos_dir_config_merge(apr_pool_t *p, void *basev, void *addv) {
  qos_dir_config *b = (qos_dir_config *)basev;
  qos_dir_config *o = (qos_dir_config *)addv;
  qos_dir_config *dconf = apr_pcalloc(p, sizeof(qos_rfilter_t));
  if(o->headerfilter != -1) {
    dconf->headerfilter = o->headerfilter;
  } else {
    dconf->headerfilter = b->headerfilter;
  }
  if(o->inheritoff) {
    dconf->rfilter_table = o->rfilter_table;
  } else {
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(b->rfilter_table)->elts;
    dconf->rfilter_table = apr_table_make(p, 1);
    for(i = 0; i < apr_table_elts(b->rfilter_table)->nelts; ++i) {
      if(entry[i].key[0] == '+') {
        apr_table_setn(dconf->rfilter_table, entry[i].key, entry[i].val);
      }
    }
    entry = (apr_table_entry_t *)apr_table_elts(o->rfilter_table)->elts;
    for(i = 0; i < apr_table_elts(o->rfilter_table)->nelts; ++i) {
      if(entry[i].key[0] == '+') {
        apr_table_setn(dconf->rfilter_table, entry[i].key, entry[i].val);
      }
    }
    for(i = 0; i < apr_table_elts(o->rfilter_table)->nelts; ++i) {
      if(entry[i].key[0] == '-') {
        char *id = apr_psprintf(p, "+%s", &entry[i].key[1]);
        apr_table_unset(dconf->rfilter_table, id);
      }
    }
  }
  return dconf;
}

static void *qos_srv_config_create(apr_pool_t *p, server_rec *s) {
  qos_srv_config *sconf;
  apr_status_t rv;
  apr_pool_t *act_pool;
  apr_pool_create(&act_pool, NULL);
  sconf =(qos_srv_config *)apr_pcalloc(p, sizeof(qos_srv_config));
  sconf->pool = p;
  sconf->location_t = apr_table_make(sconf->pool, 2);
  sconf->error_page = NULL;
  sconf->connect_timeout = -1;
  sconf->act = (qs_actable_t *)apr_pcalloc(act_pool, sizeof(qs_actable_t));
  sconf->act->pool = act_pool;
  sconf->act->ppool = s->process->pool;
  sconf->act->generation = ap_my_generation;
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
                 QOS_LOG_PFX(006)"could create mutex: %s", buf);
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
  sconf->hfilter_table = apr_table_make(p, 1);
  {
    int len = EVP_MAX_KEY_LENGTH;
    unsigned char *rand = apr_pcalloc(p, len);
    RAND_bytes(rand, len);
    EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL, rand, len, 1, sconf->key, NULL);
  }
#ifdef QS_INTERNAL_TEST
  {
    int i;
    sconf->testip = apr_table_make(sconf->pool, QS_SIM_IP_LEN);
    sconf->enable_testip = 1;
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
static void *qos_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  qos_srv_config *b = (qos_srv_config *)basev;
  qos_srv_config *o = (qos_srv_config *)addv;
  if(apr_table_elts(b->location_t)->nelts > 0) {
    o->hfilter_table = b->hfilter_table;
  }
  if((apr_table_elts(o->location_t)->nelts > 0) ||
     (o->max_conn != -1)) {
    o->connect_timeout = b->connect_timeout;
#ifdef QS_INTERNAL_TEST
    o->enable_testip = b->enable_testip;
#endif
    if(apr_table_elts(o->hfilter_table)->nelts == 0) {
      qos_load_headerfilter(p, o->hfilter_table);
    }
    return o;
  }
  if(apr_table_elts(b->hfilter_table)->nelts == 0) {
    qos_load_headerfilter(p, b->hfilter_table);
  }
  return b;
}

/**
 * command to define the concurrent request limitation for a location
 */
const char *qos_loc_con_cmd(cmd_parms *cmd, void *dcfg, const char *loc, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, loc);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, loc);
  }
  rule->limit = atoi(limit);
  if(rule->limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  rule->regex = NULL;
  apr_table_setn(sconf->location_t, loc, (char *)rule);
  return NULL;
}

/**
 * command to define the req/sec limitation for a location
 */
const char *qos_loc_rs_cmd(cmd_parms *cmd, void *dcfg, const char *loc, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, loc);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, loc);
  }
  rule->req_per_sec_limit = atol(limit);
  if(rule->req_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  rule->regex = NULL;
  apr_table_setn(sconf->location_t, loc, (char *)rule);
  return NULL;
}

/**
 * command to define the kbytes/sec limitation for a location
 */
const char *qos_loc_bs_cmd(cmd_parms *cmd, void *dcfg, const char *loc, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, loc);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, loc);
  }
  rule->kbytes_per_sec_limit = atol(limit);
  if(rule->kbytes_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  rule->regex = NULL;
  apr_table_setn(sconf->location_t, loc, (char *)rule);
  return NULL;
}

/**
 * defines the maximum of concurrent requests matching the specified
 * request line pattern
 */
const char *qos_match_con_cmd(cmd_parms *cmd, void *dcfg, const char *match, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, match);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, match);
  }
  rule->limit = atoi(limit);
  if(rule->limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  apr_table_setn(sconf->location_t, match, (char *)rule);
  return NULL;
}

/**
 * defines the maximum requests/sec for the matching request line pattern
 */
const char *qos_match_rs_cmd(cmd_parms *cmd, void *dcfg, const char *match, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, match);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, match);
  }
  rule->req_per_sec_limit = atol(limit);
  if(rule->req_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  apr_table_setn(sconf->location_t, match, (char *)rule);
  return NULL;
}

/**
 * defines the maximum kbytes/sec for the matching request line pattern
 */
const char *qos_match_bs_cmd(cmd_parms *cmd, void *dcfg, const char *match, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, match);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, match);
  }
  rule->kbytes_per_sec_limit = atol(limit);
  if(rule->kbytes_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  apr_table_setn(sconf->location_t, match, (char *)rule);
  return NULL;
}

/**
 * sets the default limitation of cuncurrent requests
 */
const char *qos_loc_con_def_cmd(cmd_parms *cmd, void *dcfg, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  return qos_loc_con_cmd(cmd, dcfg, "/", limit);
}

/**
 * defines custom error page
 */
const char *qos_error_page_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
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
const char *qos_cookie_name_cmd(cmd_parms *cmd, void *dcfg, const char *name) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->cookie_name = apr_pstrdup(cmd->pool, name);
  return NULL;
}

const char *qos_cookie_path_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->cookie_path = apr_pstrdup(cmd->pool, path);
  return NULL;
}

const char *qos_timeout_cmd(cmd_parms *cmd, void *dcfg, const char *sec) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_age = atoi(sec);
  if(sconf->max_age == 0) {
    return apr_psprintf(cmd->pool, "%s: timeout must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

const char *qos_key_cmd(cmd_parms *cmd, void *dcfg, const char *seed) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL,
                 (const unsigned char *)seed, strlen(seed), 1, sconf->key, NULL);
  return NULL;
}

/**
 * name of the http header to mark a vip
 */
const char *qos_header_name_cmd(cmd_parms *cmd, void *dcfg, const char *name) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->header_name = apr_pstrdup(cmd->pool, name);
  return NULL;
}

/**
 * max concurrent connections per server
 */
const char *qos_max_conn_cmd(cmd_parms *cmd, void *dcfg, const char *number) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_conn = atoi(number);
  if(sconf->max_conn == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

/**
 * disable keep-alive
 */
const char *qos_max_conn_close_cmd(cmd_parms *cmd, void *dcfg, const char *number) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_conn_close = atoi(number);
  if(sconf->max_conn_close == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

/**
 * max concurrent connections per client ip
 */
const char *qos_max_conn_ip_cmd(cmd_parms *cmd, void *dcfg, const char *number) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_conn_per_ip = atoi(number);
  if(sconf->max_conn_per_ip == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

/**
 * ip address without any limitation
 */
const char *qos_max_conn_ex_cmd(cmd_parms *cmd, void *dcfg, const char *addr) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  if(addr[strlen(addr)-1] == '.') {
    /* address range */
    apr_table_add(sconf->exclude_ip, addr, "r");
  } else {
    /* single ip */
    apr_table_add(sconf->exclude_ip, addr, "s");
  }
  return NULL;
}

const char *qos_max_conn_timeout_cmd(cmd_parms *cmd, void *dcfg, const char *sec) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->connect_timeout = atoi(sec);
  if(sconf->connect_timeout == 0) {
    return apr_psprintf(cmd->pool, "%s: seconds must be a numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

/**
 * generic filter command
 */
const char *qos_deny_cmd(cmd_parms *cmd, void *dcfg,
                         const char *id, const char *action, const char *pcres,
                         qs_rfilter_type_e type, int options) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  qos_rfilter_t *flt = apr_pcalloc(cmd->pool, sizeof(qos_rfilter_t));
  const char *errptr = NULL;
  int erroffset;
  flt->type = type;
  if(((id[0] != '+') && (id[0] != '-')) || (strlen(id) < 2)) {
    return apr_psprintf(cmd->pool, "%s: invalid rule id", 
                        cmd->directive->directive);
  }
  flt->id = apr_pstrdup(cmd->pool, &id[1]);
  if(strcasecmp(action, "log") == 0) {
    flt->action = QS_LOG;
  } else if(strcasecmp(action, "deny") == 0) {
    flt->action = QS_DENY;
  } else {
    return apr_psprintf(cmd->pool, "%s: invalid action", 
                        cmd->directive->directive);
  }
  flt->pr = pcre_compile(pcres, PCRE_DOTALL | options, &errptr, &erroffset, NULL);
  if(flt->pr == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        erroffset, errptr);
  }
  apr_pool_cleanup_register(cmd->pool, flt->pr, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  flt->text = apr_pstrdup(cmd->pool, pcres);
  apr_table_setn(dconf->rfilter_table, id, (char *)flt);
  return NULL;
}
const char *qos_deny_rql_cmd(cmd_parms *cmd, void *dcfg,
                             const char *id, const char *action, const char *pcres) {
  return qos_deny_cmd(cmd, dcfg, id, action, pcres, QS_DENY_REQUEST_LINE, PCRE_CASELESS);
}
const char *qos_deny_path_cmd(cmd_parms *cmd, void *dcfg,
                              const char *id, const char *action, const char *pcres) {
  return qos_deny_cmd(cmd, dcfg, id, action, pcres, QS_DENY_PATH, PCRE_CASELESS);
}
const char *qos_deny_query_cmd(cmd_parms *cmd, void *dcfg,
                               const char *id, const char *action, const char *pcres) {
  return qos_deny_cmd(cmd, dcfg, id, action, pcres, QS_DENY_QUERY, PCRE_CASELESS);
}
const char *qos_permit_uri_cmd(cmd_parms *cmd, void *dcfg,
                               const char *id, const char *action, const char *pcres) {
  return qos_deny_cmd(cmd, dcfg, id, action, pcres, QS_PERMIT_URI, 0);
}

const char *qos_denyinheritoff_cmd(cmd_parms *cmd, void *dcfg) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  dconf->inheritoff = 1;
  return NULL;
}

/* enables/disables header filter */
const char *qos_headerfilter_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  if(apr_table_elts(sconf->hfilter_table)->nelts == 0) {
    char *msg = qos_load_headerfilter(cmd->pool, sconf->hfilter_table);
    if(msg != NULL) return msg;
  }
  dconf->headerfilter = flag;
  return NULL;
}

/* set custom header rules (global only) */
const char *qos_headerfilter_rule_cmd(cmd_parms *cmd, void *dcfg, const char *header, const char *rule) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *errptr = NULL;
  int erroffset;
  pcre *p = NULL;
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if(apr_table_elts(sconf->hfilter_table)->nelts == 0) {
    char *msg = qos_load_headerfilter(cmd->pool, sconf->hfilter_table);
    if(msg != NULL) return msg;
  }
  p = pcre_compile(rule, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(p == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre %s at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        rule,
                        erroffset, errptr);
  }
  apr_table_setn(sconf->hfilter_table, header, (char *)p);
  apr_pool_cleanup_register(cmd->pool, p, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  return NULL;
}

#ifdef QS_INTERNAL_TEST
const char *qos_disable_int_ip_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->enable_testip = flag;
  return NULL;
}
#endif

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
  AP_INIT_TAKE2("QS_LocRequestPerSecLimit", qos_loc_rs_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestPerSecLimit <location> <number>, defines the allowed"
                " number of requests per second to a location. Requests are limited"
                " by adding a delay to each requests. This directive should be used"
                " in conjunction with QS_LocRequestLimit only."),
  AP_INIT_TAKE2("QS_LocKBytesPerSecLimit", qos_loc_bs_cmd, NULL,
                RSRC_CONF,
                "QS_LocKBytesPerSecLimit <location> <number>, defined the allowed"
                " download bandwidth to the defined kbytes per second. Responses are"
                "slowed by adding a delay to each response (non-linear, bigger files"
                " get longer delay than smaller ones). This directive should be used"
                " in conjunction with QS_LocRequestLimit only."),
  AP_INIT_TAKE2("QS_LocRequestLimitMatch", qos_match_con_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestLimitMatch <regex> <number>, defines the number of"
                " concurrent requests to the uri (path and query) pattern."
                " Default is defined by the QS_LocRequestLimitDefault directive."),
  AP_INIT_TAKE2("QS_LocRequestPerSecLimitMatch", qos_match_rs_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestPerSecLimitMatch <regex> <number>, defines the allowed"
                " number of requests per second to the uri (path and query) pattern."
                " Requests are limited by adding a delay to each requests."
                " This directive should be used in conjunction with"
                " QS_LocRequestLimitMatch only."),
  AP_INIT_TAKE2("QS_LocKBytesPerSecLimitMatch", qos_match_bs_cmd, NULL,
                RSRC_CONF,
                "QS_LocKBytesPerSecLimit <regex> <number>, defined the allowed"
                " download bandwidth to the defined kbytes per second. Responses are"
                "slowed by adding a delay to each response (non-linear, bigger files"
                " get longer delay than smaller ones). This directive should be used"
                " in conjunction with QS_LocRequestLimitMatch only."),
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
  AP_INIT_TAKE1("QS_SrvMaxConnTimeout", qos_max_conn_timeout_cmd, NULL,
                RSRC_CONF,
                "-"),
  AP_INIT_TAKE1("QS_SrvConnTimeout", qos_max_conn_timeout_cmd, NULL,
                RSRC_CONF,
                "QS_SrvConnTimeout <seconds>, defines the inital timeout"
                " a client must send the HTTP request on a new TCP"
                " connection. Default is the timeout defined by the"
                " Apache standard Timeout directive."),
  /* generic request filter */
  AP_INIT_TAKE3("QS_DenyRequestLine", qos_deny_rql_cmd, NULL,
                ACCESS_CONF,
                "QS_DenyRequestLine '+'|'-'<id> 'log'|'deny' <pcre>, generic"
                " request line (method, path, query and protocol) filter used"
                " to deny access for requests matching the defined expression (pcre)."
                " '+' adds a new rule while '-' removes a rule for a location."
                " The action is either 'log' (access is granted but rule"
                " match is logged) or 'deny' (access is denied)"),
  AP_INIT_TAKE3("QS_DenyPath", qos_deny_path_cmd, NULL,
                ACCESS_CONF,
                "QS_DenyPath, same as QS_DenyRequestLine but applied to the"
                " path only."),
  AP_INIT_TAKE3("QS_DenyQuery", qos_deny_query_cmd, NULL,
                ACCESS_CONF,
                "QS_DenyQuery, same as QS_DenyRequestLine but applied to the"
                " query only."),
  AP_INIT_TAKE3("QS_PermitUri", qos_permit_uri_cmd, NULL,
                ACCESS_CONF,
                "QS_PermitUri, '+'|'-'<id> 'log'|'deny' <pcre>, generic"
                " request filter applied to the request uri (path and query)."
                " Only requests matching at least one QS_PermitUri pattern are"
                " allowed. If a QS_PermitUri pattern has been defined an the"
                " request does not match any rule, the request is denied albeit of"
                " any server resource availability (white list). All rules"
                " must define the same action. pcre is case sensitve."),
  AP_INIT_NO_ARGS("QS_DenyInheritanceOff", qos_denyinheritoff_cmd, NULL,
                  ACCESS_CONF,
                  "QS_DenyInheritanceOff, disable inheritance of QS_Deny* and QS_Permit*"
                  " directives to a location."),
  AP_INIT_FLAG("QS_HeaderFilter", qos_headerfilter_cmd, NULL,
               ACCESS_CONF,
               "QS_HeaderFilter 'on'|'off'"),
  AP_INIT_TAKE2("QS_HeaderFilterRule", qos_headerfilter_rule_cmd, NULL,
                RSRC_CONF,
                "QS_HeaderFilterRule <header> <pcre>"),
#ifdef QS_INTERNAL_TEST
  AP_INIT_FLAG("QS_EnableInternalIPSimulation", qos_disable_int_ip_cmd, NULL,
               RSRC_CONF,
               ""),
#endif
  NULL,
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void qos_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_setenvif.c", NULL };
  ap_hook_post_config(qos_post_config, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_child_init(qos_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_pre_connection(qos_pre_connection, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_process_connection(qos_process_connection, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_read_request(qos_post_read_request, pre, NULL, APR_HOOK_LAST);
  ap_hook_header_parser(qos_header_parser, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_handler(qos_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(qos_logger, NULL, NULL, APR_HOOK_FIRST);

  ap_register_input_filter("qos-in-filter", qos_in_filter, NULL, AP_FTYPE_CONNECTION);
  ap_register_output_filter("qos-out-filter", qos_out_filter, NULL, AP_FTYPE_RESOURCE);
  ap_register_output_filter("qos-out-filter-delay", qos_out_filter_delay, NULL, AP_FTYPE_RESOURCE);
  ap_hook_insert_filter(qos_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);

}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA qos_module ={ 
  STANDARD20_MODULE_STUFF,
  qos_dir_config_create,                    /**< dir config creater */
  qos_dir_config_merge,                     /**< dir merger */
  qos_srv_config_create,                    /**< server config */
  qos_srv_config_merge,                     /**< server merger */
  qos_config_cmds,                          /**< command table */
  qos_register_hooks,                       /**< hook registery */
};
