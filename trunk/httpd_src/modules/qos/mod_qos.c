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
 * Copyright (C) 2007-2008 Pascal Buchbinder
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
static const char revision[] = "$Id: mod_qos.c,v 5.83 2008-06-25 20:02:57 pbuchbinder Exp $";
static const char g_revision[] = "7.3";

/************************************************************************
 * Includes
 ***********************************************************************/
/* std */
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>

/* mod_qos requires OpenSSL */
#include <openssl/rand.h>
#include <openssl/evp.h>

/* apache */
#include <httpd.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_connection.h>
#include <http_config.h>
#include <http_log.h>
#include <util_filter.h>
#include <ap_mpm.h>
#include <scoreboard.h>

/* apr / scrlib */
#include <pcre.h>
#include <apr_strings.h>
#include <apr_base64.h>

/* additional modules */
#include "mod_status.h"

/************************************************************************
 * defines
 ***********************************************************************/
#define QOS_LOG_PFX(id)  "mod_qos("#id"): "
#define QOS_RAN 10
#define QOS_MAX_AGE "3600"
#define QOS_COOKIE_NAME "MODQOS"
#define QS_SIM_IP_LEN 100
#define QS_USR_SPE "mod_qos::user"
#define QS_REC_COOKIE "mod_qos::gc"
/* netmask 255.255.240.0 */
#define QS_NETMASK 16
#define QS_NETMASK_MOD (QS_NETMASK * 65536)

#define QS_PKT_RATE_INIT  220
#define QS_PKT_RATE_MIN   30
#define QS_PKT_RATE_TH    3

/* this is the measure rate for QS_SrvRequestRate which may be increased
   to 10 or 30 seconds in order to compensate bandwidth variations */
#ifndef QS_REQ_RATE_TM
#define QS_REQ_RATE_TM    5
#endif

#define QS_MAX_DELAY 5000

#define QOS_MAGIC_LEN 8
static char qs_magic[QOS_MAGIC_LEN] = "qsmagic";

/************************************************************************
 * structures
 ***********************************************************************/

typedef struct {
  unsigned long ip;
  /* prefer */
  int vip;
  time_t lowrate;
  /* ev block */
  time_t time;
  int block;
  time_t block_time;
  /* ev/sec */
  time_t interval;
  long req;
  long req_per_sec;
  int req_per_sec_block_rate;
} qos_s_entry_t;

typedef struct {
  /* index */
  qos_s_entry_t **ipd;
  qos_s_entry_t **timed;
  /* shm */
  apr_shm_t *m;
  char *lock_file;
  apr_global_mutex_t *lock;
  /* size */
  int num;
  int max;
  int msize;
  /* data */
  int connections;
} qos_s_t;

typedef enum  {
  QS_CONN_STATE_NEW = 0,
  QS_CONN_STATE_HEAD,
  QS_CONN_STATE_BODY,
  QS_CONN_STATE_CHUNKED,
  QS_CONN_STATE_KEEP,
  QS_CONN_STATE_END
} qs_conn_state_e;

typedef enum  {
  QS_FLT_ACTION_DROP,
  QS_FLT_ACTION_DENY
} qs_flt_action_e;

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

typedef struct {
  char *variable1;
  char *variable2;
  char *name;
  char *value;
} qos_setenvif_t;

/**
 * generic request filter
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
  qs_conn_state_e status;
  apr_off_t cl_val;
  conn_rec *c;
  request_rec *r;
  /* upload bandwidth (received bytes and start time) */
  time_t time;
  apr_size_t nbytes;
  int shutdown;
  int errors;
  /* packet recv size rate: */
  apr_size_t bytes;
  int count;
  int lowrate;
} qos_ifctx_t;

/**
 * list of in_filter ctx
 */
typedef struct {
  apr_table_t *table;
#if APR_HAS_THREADS
  apr_thread_mutex_t *lock;
  apr_thread_t *thread;
#endif
  int exit;
} qos_ifctx_list_t;

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
  /** pointer to lock of the actable */
  apr_global_mutex_t *lock;
  /** location rules */
  char *url;
  int url_len;
  char *event;
#ifdef AP_REGEX_H
  ap_regex_t *regex;
  ap_regex_t *condition;
#else
  regex_t *regex;
  regex_t *condition;
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
  int has_events;
  /** mutex */
  char *lock_file;
  apr_global_mutex_t *lock;
  /** ip/conn data */
  qs_conn_t *c;
  unsigned int timeout;
  /* settings */
  int child_init;
  int generation;
} qs_actable_t;

/**
 * network table (total connections, vip connections, first update, last update)
 */
typedef struct qs_netstat_st {
  //  int counter;
  int vip;
  //  time_t first;
  //  time_t last;
} qs_netstat_t;

/**
 * user space
 */
typedef struct {
  int server_start;
  apr_table_t *act_table;
  /* source ip stat */
  char *m_file;
  apr_shm_t *m;
  char *lock_file;
  apr_global_mutex_t *lock;
  int connections;
  qs_netstat_t *netstat;
  qos_s_t *qos_cc;
} qos_user_t;

/**
 * directory config
 */
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
  apr_table_t *setenvif_t;
  apr_table_t *setenvstatus_t;
  apr_table_t *setenvresheader_t;
  apr_table_t *setenvresheadermatch_t;
  char *cookie_name;
  char *cookie_path;
  int max_age;
  unsigned char key[EVP_MAX_KEY_LENGTH];
  char *header_name;
  char *ip_header_name;
  int vip_user;
  int vip_ip_user;
  int max_conn;
  int max_conn_close;
  int max_conn_per_ip;
  apr_table_t *exclude_ip;
  int req_rate;
  qos_ifctx_list_t *inctx_t;
  apr_table_t *hfilter_table;
#ifdef QS_INTERNAL_TEST
  apr_table_t *testip;
  int enable_testip;
#endif
  int net_prefer;
  int net_prefer_limit;
  /* client control */
  int has_qos_cc;
  int qos_cc_size;
  int qos_cc_prefer;
  int qos_cc_prefer_limit;
  int qos_cc_event;
  int qos_cc_block;
  int qos_cc_block_time;
} qos_srv_config;

/**
 * connection configuration
 */
typedef struct {
  unsigned long ip;
  conn_rec *c;
  char *evmsg;
  qos_srv_config *sconf;
  int is_vip;           /* is vip, either by request or by session */
  int is_vip_by_header; /* received vip header from application/or auth. user */
  int has_lowrate;
} qs_conn_ctx;

/**
 * request configuration
 */
typedef struct {
  qs_acentry_t *entry;
  qs_acentry_t *entry_cond;
  char *evmsg;
  int is_vip;
} qs_req_ctx;

/**
 * rule set
 */
typedef struct {
  char *url;
  char *event;
  int limit;
#ifdef AP_REGEX_H
  /* apache 2.2 */
  ap_regex_t *regex;
  ap_regex_t *condition;
#else
  /* apache 2.0 */
  regex_t *regex;
  regex_t *condition;
#endif
  long req_per_sec_limit;
  long kbytes_per_sec_limit;
} qs_rule_ctx_t;

typedef struct {
  const char* name;
  const char* pcre;
  qs_flt_action_e action;
} qos_her_t;

typedef struct {
  char *text;
  pcre *pcre;
  qs_flt_action_e action;
} qos_fhlt_r_t;

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
static const qos_her_t qs_header_rules[] = {
#define QS_URL_UNRESERVED  "a-zA-Z0-9-\\._~% "
#define QS_URL_GEN         ":/\\?#\\[\\]@"
#define QS_URL_SUB         "!$&'\\(\\)\\*\\+,;="
#define QS_URL             "["QS_URL_UNRESERVED""QS_URL_GEN""QS_URL_SUB"]"
#define QS_B64_SP          "[a-zA-Z0-9 \\+/\\$=:]"
#define QS_H_ACCEPT        "[a-zA-Z0-9\\-_\\*\\+]+/[a-zA-Z0-9\\-_\\*\\+\\.]+(;[ ]?[a-zA-Z0-9]+=[0-9]+)?[ ]?(;[ ]?q=[0-9\\.]+)?"
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
  { "Accept", "^("QS_H_ACCEPT"){1}([ ]?,[ ]?"QS_H_ACCEPT")*$", QS_FLT_ACTION_DROP },
  { "Accept-Charset", "^("QS_H_ACCEPT_C"){1}([ ]?,[ ]?"QS_H_ACCEPT_C")*$", QS_FLT_ACTION_DROP },
  { "Accept-Encoding", "^("QS_H_ACCEPT_E"){1}([ ]?,[ ]?"QS_H_ACCEPT_E")*$", QS_FLT_ACTION_DROP },
  { "Accept-Language", "^("QS_H_ACCEPT_L"){1}([ ]?,[ ]?"QS_H_ACCEPT_L")*$", QS_FLT_ACTION_DROP },
  { "Authorization", "^"QS_B64_SP"+$", QS_FLT_ACTION_DROP },
  { "Cache-Control", "^("QS_H_CACHE"){1}([ ]?,[ ]?"QS_H_CACHE")*$", QS_FLT_ACTION_DROP },
  { "Connection", "^([teTE]+,[ ]?)?([a-zA-Z0-9\\-]+){1}([ ]?,[ ]?[teTE]+)?$", QS_FLT_ACTION_DROP },
  { "Content-Encoding", "^[a-zA-Z0-9\\-]+$", QS_FLT_ACTION_DENY },
  { "Content-Language", "^[a-zA-Z0-9\\-]+$", QS_FLT_ACTION_DROP },
  { "Content-Length", "^[0-9]+$", QS_FLT_ACTION_DENY },
  { "Content-Location", "^"QS_URL"+$", QS_FLT_ACTION_DENY },
  { "Content-md5", "^"QS_B64_SP"$", QS_FLT_ACTION_DENY },
  { "Content-Range", "^.*$", QS_FLT_ACTION_DENY },
  { "Content-Type", "^("QS_H_CONTENT"){1}([ ]?,[ ]?"QS_H_CONTENT")*$", QS_FLT_ACTION_DENY },
  { "Cookie", "^"QS_H_COOKIE"+$", QS_FLT_ACTION_DROP },
  { "Cookie2", "^"QS_H_COOKIE"+$", QS_FLT_ACTION_DROP },
  { "Expect", "^"QS_H_EXPECT"+$", QS_FLT_ACTION_DROP },
  { "From", "^"QS_H_FROM"+$", QS_FLT_ACTION_DROP },
  { "Host", "^"QS_H_HOST"+$", QS_FLT_ACTION_DROP },
  { "If-Match", "^"QS_H_IFMATCH"+$", QS_FLT_ACTION_DROP },
  { "If-Modified-Since", "^"QS_H_DATE"+$", QS_FLT_ACTION_DROP },
  { "If-None-Match", "^"QS_H_IFMATCH"+$", QS_FLT_ACTION_DROP },
  { "If-Range", "^"QS_H_IFMATCH"+$", QS_FLT_ACTION_DROP },
  { "If-Unmodified-Since", "^"QS_H_DATE"+$", QS_FLT_ACTION_DROP },
  { "Keep-Alive", "^[0-9]+$", QS_FLT_ACTION_DROP },
  { "Max-Forwards", "^[0-9]+$", QS_FLT_ACTION_DROP },
  { "Proxy-Authorization", "^"QS_B64_SP"$", QS_FLT_ACTION_DROP },
  { "Pragma", "^"QS_H_PRAGMA"+$", QS_FLT_ACTION_DROP },
  { "Range", "^"QS_URL"+$", QS_FLT_ACTION_DROP },
  { "Referer", "^"QS_URL"+$", QS_FLT_ACTION_DROP },
  { "TE", "^("QS_H_TE"){1}([ ]?,[ ]?"QS_H_TE")*$", QS_FLT_ACTION_DROP },
  { "User-Agent", "^[a-zA-Z0-9\\-_\\.:;\\(\\) /\\+!=]+$", QS_FLT_ACTION_DROP },
  { "Via", "^[a-zA-Z0-9\\-_\\.:;\\(\\) /\\+!]+$", QS_FLT_ACTION_DROP },
  { "X-Forwarded-For", "^[a-zA-Z0-9\\-_\\.:]+$", QS_FLT_ACTION_DROP },
  { "X-Forwarded-Host", "^[a-zA-Z0-9\\-_\\.:]+$", QS_FLT_ACTION_DROP },
  { "X-Forwarded-Server", "^[a-zA-Z0-9\\-_\\.:]+$", QS_FLT_ACTION_DROP },
  { "X-lori-time-1", "^[0-9]+$", QS_FLT_ACTION_DROP },
  { NULL, NULL, 0 }
};

/**
 * loads the default header rules into the server configuration (see rules above)
 */
static char *qos_load_headerfilter(apr_pool_t *pool, apr_table_t *hfilter_table) {
  const char *errptr = NULL;
  int erroffset;
  const qos_her_t* elt;
  for(elt = qs_header_rules; elt->name != NULL ; ++elt) {
    qos_fhlt_r_t *he = apr_pcalloc(pool, sizeof(qos_fhlt_r_t));
    he->text = apr_pstrdup(pool, elt->pcre);
    he->pcre = pcre_compile(elt->pcre, PCRE_DOTALL, &errptr, &erroffset, NULL);
    he->action = elt->action;
    if(he->pcre == NULL) {
      return apr_psprintf(pool, "could not compile pcre %s at position %d,"
                          " reason: %s", 
                          elt->name,
                          erroffset, errptr);
    }
    apr_table_setn(hfilter_table, elt->name, (char *)he);
    apr_pool_cleanup_register(pool, he->pcre, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  }
  return NULL;
}

static char *qos_rfilter_type2text(apr_pool_t *pool, qs_rfilter_type_e type) {
  if(type == QS_DENY_REQUEST_LINE) return apr_pstrdup(pool, "QS_DenyRequestLine");
  if(type == QS_DENY_PATH) return apr_pstrdup(pool, "QS_DenyPath");
  if(type == QS_DENY_QUERY) return apr_pstrdup(pool, "QS_DenyQuery");
  if(type == QS_PERMIT_URI) return apr_pstrdup(pool, "QS_PermitUri");
  return apr_pstrdup(pool, "UNKNOWN");
}

/**
 * client ip store qos_cc_*() functions
 */
static int qos_cc_comp(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->ip > pB->ip) return 1;
  if(pA->ip < pB->ip) return -1;
  return 0;
}

static int qos_cc_comp_time(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->time > pB->time) return 1;
  if(pA->time < pB->time) return -1;
  return 0;
}

static qos_s_t *qos_cc_new(apr_pool_t *pool, int size) {
  apr_shm_t *m;
  apr_status_t res;
  int msize = sizeof(qos_s_t) + 
    (sizeof(qos_s_entry_t) * size) + 
    (2 * sizeof(qos_s_entry_t *) * size);
  int i;
  qos_s_t *s;
  qos_s_entry_t *e;
  char *file = apr_psprintf(pool, "%s_cc.mod_qos",
                            ap_server_root_relative(pool, tmpnam(NULL)));
  msize = APR_ALIGN_DEFAULT(msize) + 512;
  ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, 
               QOS_LOG_PFX(000)"create shared memory (client control): %d bytes", msize);
  res = apr_shm_create(&m, msize, file, pool);
  if(res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                 QOS_LOG_PFX(002)"could not create c-shared memory: %s (%d bytes)", buf, msize);
    return NULL;
  }
  s = apr_shm_baseaddr_get(m);
  s->m = m;
  s->lock_file = apr_psprintf(pool, "%s_ccl.mod_qos", 
                              ap_server_root_relative(pool, tmpnam(NULL)));
  res = apr_global_mutex_create(&s->lock, s->lock_file, APR_LOCK_DEFAULT, pool);
  if(res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                 QOS_LOG_PFX(004)"could not create c-mutex: %s", buf);
    apr_shm_destroy(s->m);
    return NULL;
  }
  e = (qos_s_entry_t *)&s[1];
  s->ipd = (qos_s_entry_t **)&e[size];
  s->timed = (qos_s_entry_t **)&s->ipd[size];
  s->num = 0;
  s->max = size;
  s->msize = msize;
  s->connections = 0;
  for(i = 0; i < size; i++) {
    s->ipd[i] = e;
    s->timed[i] = e;
    e++;
  }
  return s;
}

static void qos_cc_free(qos_s_t *s) {
  if(s->lock) {
    apr_global_mutex_destroy(s->lock);
  }
  if(s->m) {
    apr_shm_destroy(s->m);
  }
}

static qos_s_entry_t **qos_cc_get0(qos_s_t *s, qos_s_entry_t *pA) {
  return bsearch((const void *)&pA, (const void *)s->ipd, s->max, sizeof(qos_s_entry_t *), qos_cc_comp);
}

static qos_s_entry_t **qos_cc_set(qos_s_t *s, qos_s_entry_t *pA, time_t now) {
  qos_s_entry_t **pB;
  pA->vip = 0;
  pA->lowrate = 0;
  pA->block = 0;
  pA->block_time = 0;
  pA->interval = now;
  pA->req = 0;
  pA->req_per_sec = 0;
  pA->req_per_sec_block_rate = 0;
  qsort(s->timed, s->max, sizeof(qos_s_entry_t *), qos_cc_comp_time);
  if(s->num < s->max) {
    s->num++;
    pB = &s->timed[0];
    (*pB)->ip = pA->ip;
    (*pB)->time = now;
    qsort(s->ipd, s->max, sizeof(qos_s_entry_t *), qos_cc_comp);
  } else {
    pB = &s->timed[0];
    (*pB)->ip = pA->ip;
    (*pB)->time = now;
    qsort(s->ipd, s->max, sizeof(qos_s_entry_t *), qos_cc_comp);
  }
  return pB;
}

/**
 * returns the request id from mod_unique_id (if available)
 */
static const char *qos_unique_id(request_rec *r, const char *eid) {
  const char *uid = apr_table_get(r->subprocess_env, "UNIQUE_ID");
  apr_table_set(r->notes, "error-notes", eid);
  if(uid == NULL) {
    return apr_pstrdup(r->pool, "-");
  }
  return uid;
}

/* returns the version number of mod_qos */
static char *qos_revision(apr_pool_t *p) {
  return apr_pstrdup(p, g_revision);
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
      if(strlen(cookie_h) == 0) {
        apr_table_unset(r->headers_in, "cookie");
      } else {
        if((strncasecmp(cookie_h, "$Version=", strlen("$Version=")) == 0) &&
           (strlen(cookie_h) <= strlen("$Version=X; "))) {
          /* nothing left */
          apr_table_unset(r->headers_in, "cookie");
        } else {
          apr_table_set(r->headers_in, "cookie", cookie_h);
        }
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
        s->magic[QOS_MAGIC_LEN-1] = '\0';
        if(strcmp(qs_magic, s->magic) != 0) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                        QOS_LOG_PFX(022)"session cookie verification failed, "
                        "invalid magic, id=%s", qos_unique_id(r, "022"));
          return 0;
        }
        if(s->time < (apr_time_sec(r->request_time) - sconf->max_age)) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                        QOS_LOG_PFX(023)"session cookie verification failed, "
                        "expired, id=%s", qos_unique_id(r, "023"));
          return 0;
        }
      }
    }

    /* success */
    apr_table_set(r->notes, QS_REC_COOKIE, "");
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
  s->magic[QOS_MAGIC_LEN-1] = '\0';
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
    rctx->entry_cond = NULL;
    rctx->evmsg = NULL;
    rctx->is_vip = 0;
    ap_set_module_config(r->request_config, &qos_module, rctx);
  }
  return rctx;
}

/**
 * frees shared mem and lock at server shutdown
 */
static apr_status_t qos_destroy_netstat(void *p) {
  qos_user_t *u = p;
  if(u->server_start > 1) {
    if(u->lock) {
      apr_global_mutex_destroy(u->lock);
      u->lock = NULL;
    }
    if(u->m) {
      apr_shm_destroy(u->m);
      u->m = NULL;
    }
  }
  return APR_SUCCESS;
}

/**
 * destroy shared memory and mutexes
 */
static void qos_destroy_act(qs_actable_t *act) {
  ap_log_error(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, NULL,
               QOS_LOG_PFX(001)"cleanup shared memory: %d bytes",
               act->size);
  act->child_init = 0;
  apr_global_mutex_destroy(act->lock);
  apr_shm_destroy(act->m);
  apr_pool_destroy(act->pool);
}

static int qos_init_netstat(apr_pool_t *ppool, qos_user_t *u) {
  int elements = (256 * 256 * QS_NETMASK);
  int size = elements;
  apr_status_t res;
  int i;
  u->m_file = apr_psprintf(ppool, "%s_c.mod_qos",
                           ap_server_root_relative(ppool, tmpnam(NULL)));
  size = APR_ALIGN_DEFAULT(size * sizeof(qs_netstat_t)) + 512;
  ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, 
               QOS_LOG_PFX(000)"create shared memory (network control): %d bytes", size);
  res = apr_shm_create(&u->m, size, u->m_file, ppool);
  if(res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                 QOS_LOG_PFX(002)"could not create n-shared memory: %s (%d bytes)", buf, size);
    u->m = NULL;
    return !OK;
  }
  u->lock_file = apr_psprintf(ppool, "%s_cl.mod_qos", 
                              ap_server_root_relative(ppool, tmpnam(NULL)));
  res = apr_global_mutex_create(&u->lock, u->lock_file, APR_LOCK_DEFAULT, ppool);
  if(res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                 QOS_LOG_PFX(004)"could not create u-mutex: %s", buf);
    apr_shm_destroy(u->m);
    u->m = NULL;
    u->lock = NULL;
    return !OK;
  }
  u->netstat = apr_shm_baseaddr_get(u->m);
  for(i = 0; i < elements; i++) {
    qs_netstat_t *netstat = &u->netstat[i];
    //netstat->counter = 0;
    netstat->vip = 0;
    //netstat->first = 0;
    //netstat->last = 0;
  }
  /* note: we can't register qos_destroy_netstat() to the process pool since
   *       mod_qos may be loaded as a DSO module which gets unloaded before
   *       the process pool is deleted */
  return OK;
}

/**
 * returns the persistent configuration (restarts)
 */
static qos_user_t *qos_get_user_conf(apr_pool_t *ppool, int net_prefer) {
  void *v;
  qos_user_t *u;
  apr_pool_userdata_get(&v, QS_USR_SPE, ppool);
  u = v;
  if(v) {
    if(net_prefer && (u->m == NULL)) {
      /* net_prefer has been introduced by graceful restart */
      if(qos_init_netstat(ppool, u) != OK) return NULL;
    }
    return v;
  }
  u = (qos_user_t *)apr_pcalloc(ppool, sizeof(qos_user_t));
  u->server_start = 0;
  u->act_table = apr_table_make(ppool, 2);
  apr_pool_userdata_set(u, QS_USR_SPE, apr_pool_cleanup_null, ppool);
  u->m = NULL;
  u->lock = NULL;
  u->qos_cc = NULL;
  if(net_prefer) {
    if(qos_init_netstat(ppool, u) != OK) return NULL;
  }
  return u;
}

/**
 * tells if server is terminating immediately or not
 */
static int qos_is_graceful(qs_actable_t *act) {
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
  qos_user_t *u = qos_get_user_conf(act->ppool, 0);
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
    qos_destroy_netstat(u);
    if(u->qos_cc) {
      qos_cc_free(u->qos_cc);
      u->qos_cc = NULL;
    }
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
    (max_ip * APR_ALIGN_DEFAULT(sizeof(qs_ip_entry_t))) +
    512;
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, 
               QOS_LOG_PFX(000)"%s(%s), create shared memory (request control): %d bytes (r=%d,ip=%d)", 
               s->server_hostname == NULL ? "-" : s->server_hostname,
               s->is_virtual ? "v" : "b", act->size, rule_entries, max_ip);
  res = apr_shm_create(&act->m, act->size, act->m_file, act->pool);
  if(res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                 QOS_LOG_PFX(002)"could not create r-shared memory: %s (%d bytes)", buf, act->size);
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
    e->event = rule->event;
    if(e->event) {
      act->has_events++;
    }
    e->regex = rule->regex;
    e->condition = rule->condition;
    e->limit = rule->limit;
    if(e->limit == 0 ) {
      if((e->condition == NULL) && (e->event == NULL)) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, s,
                     QOS_LOG_PFX(003)"request level rule %s has no concurrent request limitations",
                     e->url);
      }
    }
    e->interval = time(NULL);
    e->req_per_sec_limit = rule->req_per_sec_limit;
    e->kbytes_per_sec_limit = rule->kbytes_per_sec_limit;
    e->counter = 0;
    e->lock = act->lock;
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

/**
 * returns the network address (mask using QS_NETMASK, e.g. /20)
 */
static int qos_get_net(qs_conn_ctx *cconf) {
  unsigned long net = cconf->ip; /* v4 */
  net = net % QS_NETMASK_MOD;
  return net;
}

/**
 * helper for the status viewer (unsigned long to char)
 */
static void qos_collect_ip(request_rec *r, qs_ip_entry_t *ipe, apr_table_t *entries, int limit) {
  if(ipe) {
    unsigned long ip = ipe->ip;
    int a,b,c,d;
    char *red = "style=\"background-color: rgb(240,133,135);\"";
    a = ip % 256;
    ip = ip / 256;
    b = ip % 256;
    ip = ip / 256;
    c = ip % 256;
    ip = ip / 256;
    d = ip % 256;
    apr_table_addn(entries, apr_psprintf(r->pool, "%d.%d.%d.%d</td><td %s colspan=\"3\">%d",
                                         a,b,c,d,
                                         ((limit != -1) && ipe->counter >= limit) ? red : "",
                                         ipe->counter), "");
    qos_collect_ip(r, ipe->left, entries, limit);
    qos_collect_ip(r, ipe->right, entries, limit);
  }
}

/**
 * free ip entry and put it into the free list
 */
static void qos_free_ip(qs_actable_t *act, qs_ip_entry_t *ipe) {
  ipe->next = act->c->ip_free;
  ipe->left = NULL;
  ipe->right = NULL;
  ipe->counter = 0;
  act->c->ip_free = ipe;
}

/**
 * get a free ip entry from the free list
 */
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
  apr_global_mutex_lock(cconf->sconf->act->lock);   /* @CRT1 */
  {
    qs_ip_entry_t *ipe = cconf->sconf->act->c->ip_tree;
    if(ipe == NULL) {
      ipe = qos_new_ip(cconf->sconf->act);
      if(ipe) {
        ipe->ip = cconf->ip;
        ipe->counter = 0;
        cconf->sconf->act->c->ip_tree = ipe;
      }
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
          if(ipe) {
            ipe->ip = cconf->ip;
            if(ipe->ip > last->ip) {
              last->right = ipe;
            } else {
              last->left = ipe;
            }
          }
          break;
        }
      }
    }
    if(ipe) {
      ipe->counter++;
      num = ipe->counter;
    } else {
      ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, NULL,
                   QOS_LOG_PFX(005)"failed to allocate ip entry");
    }
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
    if(ipe) {
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
    if((e->event == NULL) && (e->regex != NULL) && (e->condition == NULL)) {
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
 * returns the matching conditional regex with the lowest limitation
 */
static qs_acentry_t *qos_getcondrule_byregex(request_rec *r, qos_srv_config *sconf) {
  qs_acentry_t *ret = NULL;
  qs_actable_t *act = sconf->act;
  qs_acentry_t *e = act->entry;
  int limit = -1;
  while(e) {
    if((e->event == NULL) && (e->regex != NULL) && (e->condition != NULL)) {
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
    if((e->event == NULL) && (e->regex == NULL)) {
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
    apr_table_set(r->subprocess_env, "QS_VipRequest", "yes");
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

static int qos_ishex(char x) {
  if((x >= '0') && (x <= '9')) return 1;
  if((x >= 'a') && (x <= 'f')) return 1;
  if((x >= 'A') && (x <= 'F')) return 1;
  return 0;
}

/* url escaping (%xx) */
static int qos_unescaping(char *x) {
  int i, j, ch;
  if(x == 0) return 0;
  if (x[0] == '\0')
    return 0;
  for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
    ch = x[i];
    if (ch == '%' && isxdigit(x[i + 1]) && isxdigit(x[i + 2])) {
      ch = qos_hex2c(&x[i + 1]);
      i += 2;
    } else if (ch == '\\' && (x[i + 1] == 'x') && qos_ishex(x[i + 2]) && qos_ishex(x[i + 3])) {
      ch = qos_hex2c(&x[i + 2]);
      i += 3;
    } else if (ch == '+') {
      ch = ' ';
    }
    x[j] = ch;
  }
  x[j] = '\0';
  return j;
}

/**
 * processes the per location rules QS_Permit* and QS_Deny*
 */
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
  /* process black and white list rules in one loop */
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
                      QOS_LOG_PFX(040)"access denied, %s rule id: %s (%s),"
                      " action=%s, c=%s, id=%s",
                      qos_rfilter_type2text(r->pool, rfilter->type),
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

/**
 * request header filter, drops headers which are not allowed
 */
static int qos_header_filter(request_rec *r, qos_srv_config *sconf) {
  apr_table_t *delete = apr_table_make(r->pool, 1);
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(r->headers_in)->elts;
  for(i = 0; i < apr_table_elts(r->headers_in)->nelts; i++) {
    qos_fhlt_r_t *he = (qos_fhlt_r_t *)apr_table_get(sconf->hfilter_table, entry[i].key);
    if(he) {
      if(pcre_exec(he->pcre, NULL, entry[i].val, strlen(entry[i].val), 0, 0, NULL, 0) < 0) {
        if(he->action == QS_FLT_ACTION_DENY) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        QOS_LOG_PFX(043)"access denied, header: \'%s: %s\', c=%s, id=%s",
                        entry[i].key, entry[i].val,
                        r->connection->remote_ip == NULL ? "-" : r->connection->remote_ip,
                        qos_unique_id(r, "043"));
          return HTTP_FORBIDDEN;
        }
        apr_table_add(delete, entry[i].key, entry[i].val);
      }
    } else {
      apr_table_add(delete, entry[i].key, entry[i].val);
    }
  }
  entry = (apr_table_entry_t *)apr_table_elts(delete)->elts;
  for(i = 0; i < apr_table_elts(delete)->nelts; i++) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX(042)"drop header: \'%s: %s\', c=%s, id=%s",
                  entry[i].key, entry[i].val,
                  r->connection->remote_ip == NULL ? "-" : r->connection->remote_ip,
                  qos_unique_id(r, "042"));
    apr_table_unset(r->headers_in, entry[i].key);
  }
  return APR_SUCCESS;
}

/**
 * returns list of all query name=value pairs
 */
static apr_table_t *qos_get_query_table(request_rec *r) {
  apr_table_t *av = apr_table_make(r->pool, 2);
  if(r->parsed_uri.query) {
    const char *q = apr_pstrdup(r->pool, r->parsed_uri.query);
    while(q && q[0]) {
      const char *t = ap_getword(r->pool, &q, '&');
      const char *name = ap_getword(r->pool, &t, '=');
      const char *value = t;
      if((strlen(name) > 0) && (strlen(value) > 0)) {
        apr_table_add(av, name, value);
      }
    }
  }
  return av;
}

/** add "\n" */
#define QOS_ALERT_LINE_LEN 65
static char *qos_crline(request_rec *r, const char *line) {
  char *string = "";
  const char *pos = line;
  while(pos && pos[0]) {
    int len = strlen(pos);
    if(len > QOS_ALERT_LINE_LEN) {
      string = apr_pstrcat(r->pool, string,
                           apr_psprintf(r->pool, "%.*s", QOS_ALERT_LINE_LEN, pos), "\n", NULL);
      pos = &pos[QOS_ALERT_LINE_LEN];
    } else {
      string = apr_pstrcat(r->pool, string, pos, NULL);
      pos = NULL;
    }
  }
  return string;
}

/**
 * calculates the rec/sec block rate
 */
static void qos_cal_req_sec(request_rec *r, qs_acentry_t *e) {
  if(e->req_per_sec > e->req_per_sec_limit) {
    int factor = ((e->req_per_sec * 100) / e->req_per_sec_limit) - 100;
    e->req_per_sec_block_rate = e->req_per_sec_block_rate + factor;
    if(e->req_per_sec_block_rate > QS_MAX_DELAY) {
      e->req_per_sec_block_rate = QS_MAX_DELAY;
    }
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX(050)"request rate limit, rule: %s(%ld), req/sec=%ld,"
                  " delay=%dms%s",
                  e->url, e->req_per_sec_limit,
                  e->req_per_sec, e->req_per_sec_block_rate,
                  e->req_per_sec_block_rate == QS_MAX_DELAY ? " (max)" : "");
  } else if(e->req_per_sec_block_rate > 0) {
    if(e->req_per_sec_block_rate < 50) {
      e->req_per_sec_block_rate = 0;
    } else {
      int factor = e->req_per_sec_block_rate / 6;
      e->req_per_sec_block_rate = e->req_per_sec_block_rate - factor;
    }
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                  QOS_LOG_PFX(051)"request rate limit, rule: %s(%ld), req/sec=%ld,"
                  " delay=%dms",
                  e->url, e->req_per_sec_limit,
                  e->req_per_sec, e->req_per_sec_block_rate);
  }
}

/* 
 * QS_Permit* / QS_Deny* enforcement
 */
static int qos_hp_filter(request_rec *r, qos_srv_config *sconf, qos_dir_config *dconf) {
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
  return DECLINED;
}

/**
 * QS_SetEnvResHeader(Match) (outfilter)
 */
static void qos_setenvresheader(request_rec *r, qos_srv_config *sconf) {
  apr_table_t *headers = r->headers_out;
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->setenvresheader_t)->elts;
  apr_table_entry_t *entrym = (apr_table_entry_t *)apr_table_elts(sconf->setenvresheadermatch_t)->elts;
  while(headers) {
    for(i = 0; i < apr_table_elts(sconf->setenvresheader_t)->nelts; i++) {
      const char *val = apr_table_get(headers, entry[i].key);
      if(val) {
        apr_table_set(r->subprocess_env, entry[i].key, val);
        if(strcasecmp(entry[i].val, "drop") == 0) {
          apr_table_unset(headers, entry[i].key);
        }
      }
    }
    for(i = 0; i < apr_table_elts(sconf->setenvresheadermatch_t)->nelts; i++) {
      const char *val = apr_table_get(headers, entrym[i].key);
      if(val) {
        pcre *pr = (pcre *)entrym[i].val;
        if(pcre_exec(pr, NULL, val, strlen(val), 0, 0, NULL, 0) == 0) {
          apr_table_set(r->subprocess_env, entrym[i].key, val);
        }
      }
    }
    if(headers == r->headers_out) {
      headers = r->err_headers_out;
    } else {
      headers = NULL;
    }
  }
}

/**
 * QS_SetEnvStatus (logger)
 */
static void qos_setenvstatus(request_rec *r, qos_srv_config *sconf) {
  char *code = apr_psprintf(r->pool, "%d", r->status);
  const char*var = apr_table_get(sconf->setenvstatus_t, code);
  if(var) {
    apr_table_set(r->subprocess_env, var, code);
  }
}

/**
 * QS_SetEnvIf (hp and logger)
 */
static void qos_setenvif(request_rec *r, qos_srv_config *sconf) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->setenvif_t)->elts;
  for(i = 0; i < apr_table_elts(sconf->setenvif_t)->nelts; i++) {
    qos_setenvif_t *setenvif = (qos_setenvif_t *)entry[i].val;
    if((setenvif->variable1[0] == '!') && (setenvif->variable2[0] == '!')) {
      if(!apr_table_get(r->subprocess_env, &setenvif->variable1[1]) &&
         !apr_table_get(r->subprocess_env, &setenvif->variable2[1])) {
        apr_table_set(r->subprocess_env, setenvif->name, setenvif->value);
      }
    } else if(setenvif->variable1[0] == '!') {
      if(!apr_table_get(r->subprocess_env, &setenvif->variable1[1]) &&
         apr_table_get(r->subprocess_env, setenvif->variable2)) {
        apr_table_set(r->subprocess_env, setenvif->name, setenvif->value);
      }
    } else if(setenvif->variable2[0] == '!') {
      if(apr_table_get(r->subprocess_env, setenvif->variable1) &&
         !apr_table_get(r->subprocess_env, &setenvif->variable2[1])) {
        apr_table_set(r->subprocess_env, setenvif->name, setenvif->value);
      }
    } else {
      if(apr_table_get(r->subprocess_env, setenvif->variable1) &&
         apr_table_get(r->subprocess_env, setenvif->variable2)) {
        apr_table_set(r->subprocess_env, setenvif->name, setenvif->value);
      }
    }
  }
}

/*
 * QS_RequestHeaderFilter enforcement
 */
static int qos_hp_header_filter(request_rec *r, qos_srv_config *sconf, qos_dir_config *dconf) {
  if(dconf->headerfilter > 0) {
    apr_status_t rv = qos_header_filter(r, sconf);
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
  return DECLINED;
}

/* 
 * Dynamic keep alive
 */
static void qos_hp_keepalive(request_rec *r) {
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
}

static void qos_lg_event_update(request_rec *r, time_t *t) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  qs_actable_t *act = sconf->act;
  if(act->has_events) {
    time_t now = apr_time_sec(r->request_time);
    qs_acentry_t *e = act->entry;
    *t = now;
    if(e) {
      apr_global_mutex_lock(act->lock);     /* @CRT13 */
      while(e) {
        if(e->event) {
          if(((e->event[0] != '!') && apr_table_get(r->subprocess_env, e->event)) ||
             ((e->event[0] == '!') && !apr_table_get(r->subprocess_env, &e->event[1]))) {
            e->req++;
            if(now > e->interval + 10) {
              e->req_per_sec = e->req / (now - e->interval);
              e->req = 0;
              e->interval = now;
              qos_cal_req_sec(r, e);
            }
          }
        }
        e = e->next;
      }
      apr_global_mutex_unlock(act->lock);   /* @CRT13 */
    }
  }
}

/*
 * QS_EventPerSecLimit
 * returns the max req_per_sec_block_rate
 */
static int qos_hp_event_count(request_rec *r) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  qs_actable_t *act = sconf->act;
  int req_per_sec_block = 0;
  if(act->has_events) {
    qs_acentry_t *e = act->entry;
    if(e) {
      apr_global_mutex_lock(act->lock);   /* @CRT12 */
      while(e) {
        if(e->event) {
          if(((e->event[0] != '!') && apr_table_get(r->subprocess_env, e->event)) ||
             ((e->event[0] == '!') && !apr_table_get(r->subprocess_env, &e->event[1]))) {
            if(e->req_per_sec_block_rate > req_per_sec_block) {
              req_per_sec_block = e->req_per_sec_block_rate;
            }
          }
        }
        e = e->next;
      }
      apr_global_mutex_unlock(act->lock); /* @CRT12 */
    }
  }
  return req_per_sec_block;
}

static apr_status_t qos_cleanup_inctx(void *p) {
  qos_ifctx_t *inctx = p;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                &qos_module);
#if APR_HAS_THREADS
  if(sconf->inctx_t && !sconf->inctx_t->exit) {
    apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT25 */
    apr_table_unset(sconf->inctx_t->table,
                    apr_psprintf(inctx->c->pool, "%d", (int)inctx));
    apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT25 */
  }
#endif
  return APR_SUCCESS;
}

/**
 * creates a new connection ctx (remember to set the socket, connection and timeout)
 */
static qos_ifctx_t *qos_create_ifctx(conn_rec *c) {
  qos_ifctx_t *inctx = apr_pcalloc(c->pool, sizeof(qos_ifctx_t));
  inctx->client_socket = NULL;
  inctx->status = QS_CONN_STATE_NEW;
  inctx->cl_val = 0;
  inctx->c = c;
  inctx->r = NULL;
  inctx->client_socket = NULL;
  inctx->time = 0;
  inctx->nbytes = 0;
  inctx->shutdown = 0;
  inctx->count = 5;
  inctx->bytes = QS_PKT_RATE_INIT;
  inctx->lowrate = -1;
  apr_pool_cleanup_register(c->pool, inctx, qos_cleanup_inctx, apr_pool_cleanup_null);
  return inctx;
}

/**
 * returns the context from the r->connection->input_filters
 */
static qos_ifctx_t *qos_get_ifctx(ap_filter_t *f) {
  qos_ifctx_t *inctx = NULL;
  while(f) {
    if(strcmp(f->frec->name, "qos-in-filter") == 0) {
      inctx = f->ctx;
      break;
    }
    f = f->next;
  }
  return inctx;
}

/**
 * calculates the request packet size rate (called by input filter
 */
static apr_size_t qos_packet_rate(qos_ifctx_t *inctx, apr_bucket_brigade *bb) {
  apr_bucket *b;
  apr_size_t av = 0;
  apr_size_t total = 0;
  for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
    if(b->length) {
      inctx->count++;
      inctx->bytes = inctx->bytes + b->length;
      total = total + b->length;
      av = inctx->bytes / inctx->count;
      /* client hits min packet size */
      if(av < QS_PKT_RATE_MIN) {
        inctx->lowrate++;
      }
      if(inctx->count > 10) {
        inctx->bytes = inctx->bytes - av;
        inctx->count--;
      }
    }
  }
  return total;
}

/**
 * start packet rate measure (if filter has not already been inserted)
 */
static void qos_pktrate_pc(conn_rec *c, qos_srv_config *sconf) {
  if(sconf->qos_cc_prefer_limit) {
    qos_ifctx_t *inctx = qos_get_ifctx(c->input_filters);
    if(inctx == NULL) {
      inctx = qos_create_ifctx(c);
      ap_add_input_filter("qos-in-filter", inctx, NULL, c);
    }
    inctx->lowrate = 0;
  }
}

/**
 * timeout control at process connection handler
 */
static void qos_timeout_pc(conn_rec *c, qos_srv_config *sconf) {
  if(sconf && (sconf->req_rate != -1)) {
    qos_ifctx_t *inctx = qos_get_ifctx(c->input_filters);
    if(inctx) {
      inctx->status = QS_CONN_STATE_HEAD;
      inctx->time = time(NULL);
      inctx->nbytes = 0;
#if APR_HAS_THREADS
      if(sconf->inctx_t && !sconf->inctx_t->exit) {
        apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT22 */
        apr_table_setn(sconf->inctx_t->table,
                       apr_psprintf(inctx->c->pool, "%d", (int)inctx),
                       (char *)inctx);
        apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT22 */
      }
#endif
    }
  }
}

/**
 * client contol rules at log transaction
 */
static void qos_logger_cc(request_rec *r, qos_srv_config *sconf) {
  if(sconf->has_qos_cc) {
    int lowrate = 0;
    int block_event = !apr_table_get(r->subprocess_env, "QS_Block_seen") &&
      apr_table_get(r->subprocess_env, "QS_Block");
    if(sconf->qos_cc_prefer_limit || (sconf->req_rate != -1)) {
      qos_ifctx_t *inctx = qos_get_ifctx(r->connection->input_filters);
      if(inctx) {
        if(inctx->lowrate > QS_PKT_RATE_TH) {
          lowrate = inctx->lowrate;
        }
        if(inctx->lowrate != -1) {
          inctx->count = 5;
          inctx->bytes = QS_PKT_RATE_INIT;
          inctx->lowrate = 0;
        }
        if(inctx->status > QS_CONN_STATE_NEW) {
          inctx->r = NULL;
          inctx->status = QS_CONN_STATE_KEEP;
        }
        if(inctx->shutdown) {
          lowrate++;
          inctx->shutdown = 0;
        }
      }
    }
    if(block_event || lowrate) {
      qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config, &qos_module);
      qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
      qos_s_entry_t **e = NULL;
      qos_s_entry_t new;
      time_t now = apr_time_sec(r->request_time);
      apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT19 */
      new.ip = cconf->ip;
      e = qos_cc_get0(u->qos_cc, &new);
      if(!e) {
        e = qos_cc_set(u->qos_cc, &new, time(NULL));
      }
      if(((*e)->block_time + sconf->qos_cc_block_time) < now) {
        /* reset expired events */
        (*e)->block = 0;
      }
      /* mark lowpkt client */
      if(lowrate) {
        qs_req_ctx *rctx = qos_rctx_config_get(r);
        (*e)->lowrate = apr_time_sec(r->request_time);
        rctx->evmsg = apr_pstrcat(r->pool, "r;", rctx->evmsg, NULL);
      }
      if(block_event) {
        /* increment block event */
        (*e)->block++;
        (*e)->block_time = now;
      }
      apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT19 */
      if(block_event) {
        /* only once per request */
        apr_table_set(r->subprocess_env, "QS_Block_seen", "");
      }
    }
  }
}

/**
 * client contol rules at header parser
 */
static int qos_hp_cc(request_rec *r, qos_srv_config *sconf, char **msg, char **uid) {
  int ret = DECLINED;
  if(sconf->has_qos_cc) {
    int req_per_sec_block_rate = 0;
    qos_s_entry_t **e = NULL;
    qos_s_entry_t new;
    qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config, &qos_module);
    qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
    apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT17 */
    new.ip = cconf->ip;
    e = qos_cc_get0(u->qos_cc, &new);
    if(!e) {
      e = qos_cc_set(u->qos_cc, &new, apr_time_sec(r->request_time));
    } else {
      /* update time */
      (*e)->time = apr_time_sec(r->request_time);
    }
    if(sconf->qos_cc_event) {
      time_t now = apr_time_sec(r->request_time);
      const char *v = apr_table_get(r->subprocess_env, "QS_Event");
      if(v) {
        (*e)->req++;
        if(now > (*e)->interval + 10) {
          /* calc req/sec */
          (*e)->req_per_sec = (*e)->req / (now - (*e)->interval);
          (*e)->req = 0;
          (*e)->interval = now;
          /* calc block rate */
          if((*e)->req_per_sec > sconf->qos_cc_event) {
            int factor = (((*e)->req_per_sec * 100) / sconf->qos_cc_event) - 100;
            (*e)->req_per_sec_block_rate = (*e)->req_per_sec_block_rate + factor;
            if((*e)->req_per_sec_block_rate > QS_MAX_DELAY) {
              (*e)->req_per_sec_block_rate = QS_MAX_DELAY;
            }
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          QOS_LOG_PFX(061)"request rate limit, rule: QS_Event(%d), req/sec=%ld,"
                          " delay=%dms%s",
                          sconf->qos_cc_event,
                          (*e)->req_per_sec, (*e)->req_per_sec_block_rate,
                          (*e)->req_per_sec_block_rate == QS_MAX_DELAY ? " (max)" : "");
          } else if((*e)->req_per_sec_block_rate > 0) {
            if((*e)->req_per_sec_block_rate < 50) {
              (*e)->req_per_sec_block_rate = 0;
            } else {
              int factor = (*e)->req_per_sec_block_rate / 6;
              (*e)->req_per_sec_block_rate = (*e)->req_per_sec_block_rate - factor;
            }
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                          QOS_LOG_PFX(062)"request rate limit, rule: QS_Event(%d), req/sec=%ld,"
                          " delay=%dms",
                          sconf->qos_cc_event,
                          (*e)->req_per_sec, (*e)->req_per_sec_block_rate);
          }
        }
        req_per_sec_block_rate = (*e)->req_per_sec_block_rate;
      }
    }
    if(sconf->qos_cc_block) {
      time_t now = apr_time_sec(r->request_time);
      const char *v = apr_table_get(r->subprocess_env, "QS_Block");
      if(((*e)->block_time + sconf->qos_cc_block_time) < now) {
        /* reset expired events */
        (*e)->block = 0;
      }
      if(v) {
        /* increment block event */
        (*e)->block++;
        (*e)->block_time = now;
        /* only once per request */
        apr_table_set(r->subprocess_env, "QS_Block_seen", "");
      }
      if((*e)->block >= sconf->qos_cc_block) {
        *uid = apr_pstrdup(cconf->c->pool, "060");
        *msg = apr_psprintf(cconf->c->pool, 
                            QOS_LOG_PFX(060)"access denied, QS_ClientEventBlockCount rule: "
                            "max=%d, current=%d, c=%s",
                            cconf->sconf->qos_cc_block,
                            (*e)->block,
                            cconf->c->remote_ip == NULL ? "-" : cconf->c->remote_ip);
        ret = HTTP_FORBIDDEN;
      }
    }
    apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT17 */
    if(req_per_sec_block_rate) {
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      int sec = req_per_sec_block_rate / 1000;
      int nsec = req_per_sec_block_rate % 1000;
      struct timespec delay;
      rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
      delay.tv_sec  = sec;
      delay.tv_nsec = nsec * 1000000;
      nanosleep(&delay,NULL);
    }
  }
  return ret;
}

/**
 * client control rules at process connection handler
 */
static int qos_cc_pc_filter(qs_conn_ctx *cconf, qos_user_t *u, char **msg) {
  int ret = DECLINED;
  if(cconf->sconf->has_qos_cc) {
    qos_s_entry_t **e = NULL;
    qos_s_entry_t new;
    new.ip = cconf->ip;
    apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT14 */
    e = qos_cc_get0(u->qos_cc, &new);
    if(!e) {
      e = qos_cc_set(u->qos_cc, &new, time(NULL));
    }
    /* max connections */
    if(cconf->sconf->qos_cc_prefer) {
      u->qos_cc->connections++;
      if(!(*e)->vip) {
        if(u->qos_cc->connections > cconf->sconf->qos_cc_prefer_limit) {
          *msg = apr_psprintf(cconf->c->pool, 
                              QOS_LOG_PFX(063)"access denied, QS_ClientPrefer rule (not vip): "
                              "max=%d, concurrent connections=%d, c=%s",
                              cconf->sconf->qos_cc_prefer_limit, u->qos_cc->connections,
                              cconf->c->remote_ip == NULL ? "-" : cconf->c->remote_ip);
          ret = HTTP_FORBIDDEN;
        }
      }
      if((*e)->lowrate) {
        if(u->qos_cc->connections > cconf->sconf->qos_cc_prefer_limit) {
          *msg = apr_psprintf(cconf->c->pool, 
                              QOS_LOG_PFX(064)"access denied, QS_ClientPrefer rule (low prio): "
                              "max=%d, concurrent connections=%d, c=%s",
                              cconf->sconf->qos_cc_prefer_limit, u->qos_cc->connections,
                              cconf->c->remote_ip == NULL ? "-" : cconf->c->remote_ip);
          ret = HTTP_FORBIDDEN;
        }
      }
    }
    /* blocked by event */
    if(cconf->sconf->qos_cc_block) {
      if((*e)->block >= cconf->sconf->qos_cc_block) {
        time_t now = time(NULL);
        if(((*e)->block_time + cconf->sconf->qos_cc_block_time) > now) {
          /* still blocking */
          *msg = apr_psprintf(cconf->c->pool, 
                              QOS_LOG_PFX(060)"access denied, QS_ClientEventBlockCount rule: "
                              "max=%d, current=%d, c=%s",
                              cconf->sconf->qos_cc_block,
                              (*e)->block,
                              cconf->c->remote_ip == NULL ? "-" : cconf->c->remote_ip);
          ret = HTTP_FORBIDDEN;
        } else {
          /* release */
          (*e)->block = 0;
        }
      }
    }
    apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT14 */
  }
  return ret;
}

static int qos_has_clienttable(request_rec *r) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  int has = 0;
  server_rec *s = sconf->base_server;
  while(s) {
    sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
    if(sconf->act && sconf->act->c && sconf->act->c->ip_tree) {
      has = 1;
    }
    s = s->next;
  }
  return has;
}

/************************************************************************
 * "public"
 ***********************************************************************/

/**
 * short status viewer
 */
static void qos_ext_status_short(request_rec *r) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  server_rec *s = sconf->base_server;
  qos_srv_config *bsconf = (qos_srv_config*)ap_get_module_config(s->module_config,
                                                                 &qos_module);
  while(s) {
    char *sn = apr_psprintf(r->pool, "%s.%s.%d",
                            s->is_virtual ? "v" : "b",
                            s->server_hostname == NULL ? "-" :
                            ap_escape_html(r->pool, s->server_hostname),
                            s->addrs->host_port);
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    if((s->is_virtual && (sconf != bsconf)) || !s->is_virtual) {
      qs_acentry_t *e;
      if(!s->is_virtual && sconf->has_qos_cc && sconf->qos_cc_prefer_limit) {
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
        int hc = u->qos_cc->connections; /* not synchronized ... */
        ap_rprintf(r, "%s.QS_ClientPrefer.%d[]: %d\n", sn,
                   sconf->qos_cc_prefer_limit, hc);
      }
      if(!s->is_virtual && sconf->net_prefer_limit) {
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
        int hc = u->connections; /* not synchronized ... */
        ap_rprintf(r, "%s.QS_SrvPreferNet.%d[]: %d\n", sn,
                   sconf->net_prefer_limit, hc);
      }
      /* request level */
      e = sconf->act->entry;
      while(e) {
        if((e->limit > 0) && !e->condition) {
          ap_rprintf(r, "%s.QS_LocRequestLimit%s.%d[%s]: %d\n", sn,
                     e->regex == NULL ? "" : "Match", 
                     e->limit,
                     e->url, 
                     e->counter);
        }
        if(e->req_per_sec_limit > 0) {
          ap_rprintf(r, "%s.QS_LocRequestPerSecLimit%s.%ld[%s]: %ld\n", sn,
                     e->regex == NULL ? "" : "Match", 
                     e->req_per_sec_limit,
                     e->url,
                     e->req_per_sec);
        }
        if(e->kbytes_per_sec_limit > 0) {
          ap_rprintf(r, "%s.QS_LocKBytesPerSecLimit%s.%ld[%s]: %ld\n", sn,
                     e->regex == NULL ? "" : "Match",
                     e->kbytes_per_sec_limit,
                     e->url, 
                     e->kbytes_per_sec);
        }
        if(e->condition) {
          ap_rprintf(r, "%s.QS_CondLocRequestLimitMatch.%d[%s]: %d\n", sn,
                     e->limit,
                     e->url, 
                     e->counter);
        }
        e = e->next;
      }
      if(sconf->max_conn != -1) {
          ap_rprintf(r, "%s.QS_SrvMaxConn.%d[]: %d\n", sn,
                     sconf->max_conn,
                     sconf->act->c->connections);
      }
      if(sconf->max_conn_close != -1) {
          ap_rprintf(r, "%s.QS_SrvMaxConnClose.%d[]: %d\n", sn,
                     sconf->max_conn_close,
                     sconf->act->c->connections);
      }
    }
    s = s->next;
  }
}

/**
 * viewer settings about ip address information
 */
static void qos_show_ip(request_rec *r, qos_srv_config *sconf, apr_table_t *qt) {
  int has_clienttable = qos_has_clienttable(r);
  if(has_clienttable || sconf->has_qos_cc) {
    const char *option = apr_table_get(qt, "option");
    if(strcmp(r->handler, "qos-viewer") == 0) {
      ap_rputs("<table class=\"btable\"><tbody>\n", r);
      ap_rputs(" <tr class=\"row\"><td>\n", r);
    } else {
      ap_rputs("<table border=\"1\"><tbody>\n", r);
      ap_rputs(" <tr><td>\n", r);
    }
    if(strcmp(r->handler, "qos-viewer") == 0) {
      ap_rputs("<table border=\"0\" cellpadding=\"2\" "
               "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    } else {
      ap_rputs("<table border=\"1\" cellpadding=\"2\" "
               "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    }
    ap_rputs("<tr class=\"rowe\">\n", r);
    ap_rputs("<td colspan=\"9\">viewer settings</td>", r);
    ap_rputs("</tr>\n", r);
    if(has_clienttable) {
      ap_rputs("<tr class=\"rows\">"
               "<td colspan=\"1\">client ip connections</td>", r);
      ap_rputs("<td colspan=\"8\">\n", r);
      ap_rprintf(r, "<form action=\"%s\" method=\"get\">\n",
                 ap_escape_html(r->pool, r->parsed_uri.path));
      if(!option || (option && !strstr(option, "ip")) ) {
        ap_rprintf(r, "<input name=\"option\" value=\"ip\" type=\"hidden\">\n");
        ap_rprintf(r, "<input name=\"action\" value=\"enable\" type=\"submit\">\n");
      } else {
        ap_rprintf(r, "<input name=\"option\" value=\"no\" type=\"hidden\">\n");
        ap_rprintf(r, "<input name=\"action\" value=\"disable\" type=\"submit\">\n");
      }
      ap_rputs("</form>\n", r);
      ap_rputs("</td></tr>\n", r);
    }
    if(sconf->has_qos_cc) {
      const char *address = apr_table_get(qt, "address");
      ap_rputs("<tr class=\"rows\">"
               "<td colspan=\"1\">search a client ip entry</td>\n", r); 
      ap_rputs("<td colspan=\"8\">\n", r);
      ap_rprintf(r, "<form action=\"%s\" method=\"get\">\n",
                 ap_escape_html(r->pool, r->parsed_uri.path));
      if(option && strstr(option, "ip")) {
        ap_rprintf(r, "<input name=\"option\" value=\"ip\" type=\"hidden\">\n");
      }
      ap_rprintf(r, "<input name=\"address\" value=\"%s\" type=\"text\">\n",
                 address ? ap_escape_html(r->pool, address) : "0.0.0.0");
      ap_rprintf(r, "<input name=\"action\" value=\"search\" type=\"submit\">\n");
      ap_rputs("</form>\n", r);
      ap_rputs("</td></tr>\n", r);
      if(address) {
        unsigned long ip = inet_addr(address);
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
        if(ip) {
          qos_s_entry_t **e = NULL;
          qos_s_entry_t new;
          apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT20 */
          new.ip = ip;
          e = qos_cc_get0(u->qos_cc, &new);
          if(e) {
            new.vip = (*e)->vip;
            new.lowrate = (*e)->lowrate;
            new.time = (*e)->time;
            new.block = (*e)->block;
            new.block_time = (*e)->block_time;
            new.req_per_sec = (*e)->req_per_sec;
            new.req_per_sec_block_rate = (*e)->req_per_sec_block_rate;
            new.lowrate = (*e)->lowrate;
          }
          apr_global_mutex_unlock(u->qos_cc->lock);            /* @CRT20 */
          ap_rputs("<tr class=\"rowt\"><td colspan=\"1\">IP</td>", r);
          ap_rputs("<td colspan=\"2\">last request</td>", r);
          ap_rputs("<td colspan=\"1\">vip</td>", r);
          ap_rputs("<td colspan=\"2\">blocked</td>", r);
          ap_rputs("<td colspan=\"2\">events/sec</td>", r);
          ap_rputs("<td colspan=\"1\">low prio</td>", r);
          ap_rputs("</tr>\n", r);
          ap_rprintf(r, "<tr class=\"rows\">"
                     "<td colspan=\"1\">%s</td>", ap_escape_html(r->pool, address));
          if(!e) {
            ap_rputs("<td colspan=\"8\"><i>not found</i></td>\n", r);
          } else {
            char buf[1024];
            struct tm *ptr = localtime(&new.time);
            strftime(buf, sizeof(buf), "%d.%m.%Y %H:%M:%S", ptr);
            ap_rprintf(r, "<td colspan=\"2\">%s</td>", buf);
            ap_rprintf(r, "<td colspan=\"1\">%s</td>", new.vip ? "yes" : "no");
            if(sconf->qos_cc_block_time > (time(NULL) - new.block_time)) {
              ap_rprintf(r, "<td colspan=\"1\">%s</td>", new.block ? "yes" : "no");
              ap_rprintf(r, "<td colspan=\"1\">%ld&nbsp;sec</td>", time(NULL) - new.block_time);
            } else {
              ap_rprintf(r, "<td colspan=\"2\">no</td>");
            }
            ap_rprintf(r, "<td colspan=\"1\">%ld</td>", new.req_per_sec);
            ap_rprintf(r, "<td colspan=\"1\">%d&nbsp;ms</td>", new.req_per_sec_block_rate);
            ap_rprintf(r, "<td colspan=\"1\">%s</td>\n", new.lowrate ? "yes" : "no");
          }
          ap_rputs("</tr>\n", r);
        }
      }
    }
    ap_rprintf(r, "<tr class=\"row\">"
               "<td style=\"width:28%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "</tr>");
    ap_rputs(" </tbody></table>\n", r);
    ap_rputs(" </tr></td>\n", r);
    ap_rputs("</tbody></table>\n", r);
  }
}

/**
 * status viewer, used by internal and mod_status handler
 */
static int qos_ext_status_hook(request_rec *r, int flags) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  server_rec *s = sconf->base_server;
  int i = 0;
  time_t now = apr_time_sec(r->request_time);
  qos_srv_config *bsconf = (qos_srv_config*)ap_get_module_config(s->module_config,
                                                                 &qos_module);
  apr_table_t *qt = qos_get_query_table(r);
  const char *option = apr_table_get(qt, "option");
  if (flags & AP_STATUS_SHORT) {
    qos_ext_status_short(r);
    return OK;
  }
  ap_rprintf(r, "<h2>mod_qos %s</h2>\n", ap_escape_html(r->pool, qos_revision(r->pool)));
#ifdef QS_INTERNAL_TEST
  ap_rputs("<p>TEST BINARY, NOT FOR PRODUCTIVE USE</p>\n", r);
#endif
  qos_show_ip(r, bsconf, qt);
  if(strcmp(r->handler, "qos-viewer") == 0) {
    ap_rputs("<table class=\"btable\"><tbody>\n", r);
    ap_rputs(" <tr class=\"row\"><td>\n", r);
  } else {
    ap_rputs("<hr>\n", r);
    ap_rputs("<table border=\"1\"><tbody>\n", r);
    ap_rputs(" <tr><td>\n", r);
  }
  while(s) {
    qs_acentry_t *e;
    if(strcmp(r->handler, "qos-viewer") == 0) {
      ap_rputs("<table border=\"0\" cellpadding=\"2\" "
               "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    } else {
      ap_rputs("<table border=\"1\" cellpadding=\"2\" "
               "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    }
    ap_rputs("<tr class=\"rowe\">\n", r);
    ap_rprintf(r, "<td colspan=\"9\">%s:%d (%s)</td>\n",
               s->server_hostname == NULL ? "-" : ap_escape_html(r->pool, s->server_hostname),
               s->addrs->host_port,
               s->is_virtual ? "virtual" : "base");
    ap_rputs("</tr>\n", r);
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);

    if((sconf == bsconf) && s->is_virtual) {
      ap_rputs("<tr class=\"rows\">"
               "<td colspan=\"9\"><i>uses base server settings</i></td></tr>\n", r);
    } else {
      if(!s->is_virtual && sconf->has_qos_cc) {
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
        int num = 0;
        int max = 0;
        int hc = -1;
        apr_global_mutex_lock(u->qos_cc->lock);           /* @CRT16 */
        hc = u->qos_cc->connections;
        num = u->qos_cc->num;
        max = u->qos_cc->max;
        apr_global_mutex_unlock(u->qos_cc->lock);         /* @CRT16 */
        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"6\">client control</td>"
                 "<td >max</td>"
                 "<td >limit&nbsp;</td>"
                 "<td >current&nbsp;</td>", r);
        ap_rputs("</tr>\n", r);
        ap_rprintf(r, "<tr class=\"rows\">");
        ap_rprintf(r, "<td colspan=\"6\">clients in memory</td>");
        ap_rprintf(r, "<td >%d</td>", max);
        ap_rprintf(r, "<td >&nbsp</td>");
        ap_rprintf(r, "<td >%d</td>", num);
        ap_rputs("</tr>\n", r);
        if(sconf->qos_cc_prefer) {
          ap_rprintf(r, "<tr class=\"rows\">");
          ap_rprintf(r, "<td colspan=\"6\">connections</td>");
          ap_rprintf(r, "<td >%d</td>", sconf->qos_cc_prefer);
          ap_rprintf(r, "<td >%d</td>", sconf->qos_cc_prefer_limit);
          ap_rprintf(r, "<td >%d</td>", hc);
          ap_rputs("</tr>\n", r);
        }
        /*
        if(sconf->qos_cc_block) {
          ap_rprintf(r, "<tr class=\"rows\">");
          ap_rprintf(r, "<td colspan=\"6\">block event</td>");
          ap_rprintf(r, "<td >%d</td>", sconf->qos_cc_block);
          ap_rprintf(r, "<td >&nbsp</td>");
          ap_rprintf(r, "<td >%d</td>", blocked);
          ap_rputs("</tr>\n", r);
        }
        */
      }
      /* max host connections */
      if(!s->is_virtual && sconf->net_prefer) {
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
        int hc = -1;
        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"6\">preferred networks</td>"
                 "<td >max</td>"
                 "<td >limit&nbsp;</td>"
                 "<td >current&nbsp;</td>", r);
        ap_rputs("</tr>\n", r);
        apr_global_mutex_lock(u->lock);                   /* @CRT11 */
        hc = u->connections;
        apr_global_mutex_unlock(u->lock);                 /* @CRT11 */
        ap_rprintf(r, "<!--%d--><tr class=\"rows\">", i);
        ap_rprintf(r, "<td colspan=\"6\">host connections</td>");
        ap_rprintf(r, "<td >%d</td>", sconf->net_prefer);
        ap_rprintf(r, "<td >%d</td>", sconf->net_prefer_limit);
        ap_rprintf(r, "<td >%d</td>", hc);
        ap_rputs("</tr>\n", r);
      }
      /* request level */
      e = sconf->act->entry;
      if(e) {
        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"1\">location</td>"
                 "<td colspan=\"2\">concurrent requests</td>"
                 "<td colspan=\"3\">requests/second</td>"
                 "<td colspan=\"3\">kbytes/second</td>", r);
        ap_rputs("</tr>\n", r);
        ap_rputs("<tr class=\"rowt\">"
                 "<td ></td>"
                 "<td >limit</td>"
                 "<td >current</td>"
                   "<td >wait rate</td>"
                 "<td >limit</td>"
                 "<td >current</td>"
                 "<td >wait rate</td>"
                 "<td >limit</td>"
                 "<td >current</td>", r);
          ap_rputs("</tr>\n", r);
      }
      while(e) {
        char *red = "style=\"background-color: rgb(240,133,135);\"";
        ap_rputs("<tr class=\"rows\">", r);
        ap_rprintf(r, "<!--%d--><td>%s%s</a></td>", i,
                   ap_escape_html(r->pool, qos_crline(r, e->url)),
                   e->condition == NULL ? "" : " <small>(conditional)</small>");
        if(e->limit == 0) {
          ap_rprintf(r, "<td>-</td>");
          ap_rprintf(r, "<td>-</td>");
        } else {
          ap_rprintf(r, "<td>%d</td>", e->limit);
          ap_rprintf(r, "<td %s>%d</td>",
                     ((e->counter * 100) / e->limit) > 70 ? red : "",
                     e->counter);
        }
        if(e->req_per_sec_limit == 0) {
          ap_rprintf(r, "<td>-</td>");
          ap_rprintf(r, "<td>-</td>");
          ap_rprintf(r, "<td>-</td>");
          } else {
          ap_rprintf(r, "<td %s>%d&nbsp;ms</td>",
                     e->req_per_sec_block_rate ? red : "",
                     e->req_per_sec_block_rate);
          ap_rprintf(r, "<td>%ld</td>", e->req_per_sec_limit);
          ap_rprintf(r, "<td %s>%ld</td>",
                     ((e->req_per_sec * 100) / e->req_per_sec_limit) > 70 ? red : "",
                     now > (e->interval + 11) ? 0 : e->req_per_sec);
        }
        if(e->kbytes_per_sec_limit == 0) {
            ap_rprintf(r, "<td>-</td>");
            ap_rprintf(r, "<td>-</td>");
            ap_rprintf(r, "<td>-</td>");
        } else {
          ap_rprintf(r, "<td %s>%d&nbsp;ms</td>",
                     e->kbytes_per_sec_block_rate ? red : "",
                     e->kbytes_per_sec_block_rate);
          ap_rprintf(r, "<td>%ld</td>", e->kbytes_per_sec_limit);
          ap_rprintf(r, "<td %s>%ld</td>",
                     ((e->kbytes_per_sec * 100) / e->kbytes_per_sec_limit) > 70 ? red : "",
                     now > (e->interval + 11) ? 0 : e->kbytes_per_sec);
        }
        ap_rputs("</tr>\n", r);
        e = e->next;
      }
      /* connection level */
      if(sconf) {
        char *red = "style=\"background-color: rgb(240,133,135);\"";
        qs_ip_entry_t *f;
        int c = 0;
        apr_global_mutex_lock(sconf->act->lock);   /* @CRT7 */
        f = sconf->act->c->ip_free;
        while(f) {
          c++;
          f = f->next;
        }
        apr_global_mutex_unlock(sconf->act->lock); /* @CRT7 */
        
        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"9\">connections</td>", r);
        ap_rputs("</tr>\n", r);
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<!--%d--><td colspan=\"6\">free ip entries</td>"
                   "<td colspan=\"3\">%d</td></tr>\n", i, c);
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<!--%d--><td colspan=\"6\">current connections</td>"
                   "<td %s colspan=\"3\">%d</td></tr>\n", i,
                   ( ( (sconf->max_conn_close != -1) &&
                       (sconf->act->c->connections >= sconf->max_conn_close) )  ||
                     ( (sconf->max_conn != -1) &&
                       (sconf->act->c->connections >= sconf->max_conn) ) ) ? red : "",
                   sconf->act->c->connections);
        
        if(option && strstr(option, "ip")) {
          if(sconf->act->c->connections) {
            apr_table_t *entries = apr_table_make(r->pool, 10);
            int j;
            apr_table_entry_t *entry;
            ap_rputs("<tr class=\"rowt\">"
                     "<td colspan=\"6\">client ip connections</td>"
                     "<td colspan=\"3\">current&nbsp;</td>", r);
            ap_rputs("</tr>\n", r);
            apr_global_mutex_lock(sconf->act->lock);   /* @CRT8 */
            qos_collect_ip(r, sconf->act->c->ip_tree, entries, sconf->max_conn_per_ip);
            apr_global_mutex_unlock(sconf->act->lock); /* @CRT8 */
            entry = (apr_table_entry_t *)apr_table_elts(entries)->elts;
            for(j = 0; j < apr_table_elts(entries)->nelts; j++) {
              ap_rputs("<tr class=\"rows\">", r);
              ap_rputs("<td colspan=\"6\">", r);
              ap_rprintf(r, "%s</td></tr>\n", entry[j].key);
            }
          }
        }

        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"9\">connection settings</td>", r);
        ap_rputs("</tr>\n", r);
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<td colspan=\"6\">max connections</td>");
        if(sconf->max_conn == -1) {
          ap_rprintf(r, "<td colspan=\"3\">-</td></tr>\n");
        } else {
          ap_rprintf(r, "<td colspan=\"3\">%d</td></tr>\n", sconf->max_conn);
        }
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<td colspan=\"6\">max connections with keep-alive</td>");
        if(sconf->max_conn_close == -1) {
          ap_rprintf(r, "<td colspan=\"3\">-</td></tr>\n");
        } else {
          ap_rprintf(r, "<td colspan=\"3\">%d</td></tr>\n", sconf->max_conn_close);
        }
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<td colspan=\"6\">max connections per client ip</td>");
        if(sconf->max_conn_per_ip == -1) {
          ap_rprintf(r, "<td colspan=\"3\">-</td></tr>\n");
        } else {
          ap_rprintf(r, "<td colspan=\"3\">%d</td></tr>\n", sconf->max_conn_per_ip);
        }
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<td colspan=\"6\">request rate (bytes/sec)</td>");
        if(sconf->req_rate == -1) {
          ap_rprintf(r, "<td colspan=\"3\">-</td></tr>\n");
        } else {
          ap_rprintf(r, "<td colspan=\"3\">%d</td></tr>\n", sconf->req_rate);
        }
      }
    }
    ap_rprintf(r, "<tr class=\"row\">"
               "<td style=\"width:28%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "</tr>");
    i++;
    s = s->next;
    ap_rputs("</tbody></table>\n", r);
  }
  ap_rputs(" </td></tr>\n", r);
  ap_rputs("</tbody></table>\n", r);
  if(strcmp(r->handler, "qos-viewer") != 0) {
    ap_rputs("<hr>\n", r);
  }
  return OK;
}

static void qos_disable_req_rate(server_rec *bs, const char *msg) {
  server_rec *s = bs->next;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  ap_log_error(APLOG_MARK, APLOG_ERR, 0, bs,
               QOS_LOG_PFX(008)"could not create supervisor thread (%s),"
               " disable request rate enforcement", msg);
  sconf->req_rate = -1;
  while(s) {
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    sconf->req_rate = -1;
    s = s->next;
  }
}

#if APR_HAS_THREADS
static void *qos_req_rate_thread(apr_thread_t *thread, void *selfv) {
  server_rec *bs = selfv;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  while(!sconf->inctx_t->exit) {
    time_t interval = time(NULL) - QS_REQ_RATE_TM;
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->inctx_t->table)->elts;
    sleep(1);
    apr_thread_mutex_lock(sconf->inctx_t->lock);   /* @CRT21 */
    for(i = 0; i < apr_table_elts(sconf->inctx_t->table)->nelts; i++) {
      qos_ifctx_t *inctx = (qos_ifctx_t *)entry[i].val;
      if(interval > inctx->time) {
        int rate = inctx->nbytes / QS_REQ_RATE_TM;
        if(rate < sconf->req_rate) {
          if(inctx->client_socket) {
            qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(inctx->c->conn_config,
                                                                    &qos_module);
            int level = APLOG_ERR;
            if(cconf && cconf->is_vip) {
              level = APLOG_WARNING;
              cconf->has_lowrate = 1; /* mark connection low rate */
            }
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|level, 0, inctx->c->base_server,
                         QOS_LOG_PFX(034)"%s, QS_SrvRequestRate rule: min=%d,"
                         " this connection=%d,"
                         " c=%s",
                         level == APLOG_WARNING ? "log only due QS_SrvMaxConnExcludeIP match" 
                         : "access denied",
                         sconf->req_rate, rate,
                         inctx->c->remote_ip == NULL ? "-" : inctx->c->remote_ip);
            if(cconf && cconf->is_vip) {
              inctx->time = interval + QS_REQ_RATE_TM;
              inctx->nbytes = 0;
            } else {
              apr_socket_shutdown(inctx->client_socket, APR_SHUTDOWN_READ);
            }
            /* mark slow clients (QS_ClientPrefer) even they are VIP */
            inctx->shutdown = 1;
          }
        } else {
          inctx->time = interval + QS_REQ_RATE_TM;
          inctx->nbytes = 0;
        }
      }
    }
    apr_thread_mutex_unlock(sconf->inctx_t->lock); /* @CRT21 */
  }
  apr_thread_mutex_destroy(sconf->inctx_t->lock);
  apr_thread_exit(thread, APR_SUCCESS);
  return NULL;
}

static apr_status_t qos_cleanup_req_rate_thread(void *selfv) {
  server_rec *bs = selfv;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  // apr_status_t status;
  sconf->inctx_t->exit = 1;
  // apr_thread_join(&status, sconf->inctx_t->thread);
  return APR_SUCCESS;
}
#endif

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * connection destructor
 */
static apr_status_t qos_cleanup_conn(void *p) {
  qs_conn_ctx *cconf = p;
  qos_user_t *u = qos_get_user_conf(cconf->sconf->act->ppool, 0);
  if(cconf->sconf->qos_cc_prefer) {
    apr_global_mutex_lock(u->qos_cc->lock);           /* @CRT15 */
    u->qos_cc->connections--;
    if(cconf->is_vip_by_header || cconf->has_lowrate) {
      qos_s_entry_t **e = NULL;
      qos_s_entry_t new;
      new.ip = cconf->ip;
      e = qos_cc_get0(u->qos_cc, &new);
      if(!e) {
        e = qos_cc_set(u->qos_cc, &new, time(NULL));
      }
      if(cconf->is_vip_by_header) {
        (*e)->vip = 1;
      }
      if(cconf->has_lowrate) {
        (*e)->lowrate = time(NULL);
      }
    }
    apr_global_mutex_unlock(u->qos_cc->lock);         /* @CRT15 */
  }
  if(cconf->sconf->net_prefer) {
    apr_global_mutex_lock(u->lock);                   /* @CRT10 */
    if(u->connections) u->connections--;
    if(u->connections < cconf->sconf->net_prefer_limit) {
      /* no limit reached, allow network learning ... */
      int net = qos_get_net(cconf);
      /* 1) ip client in network (nominated by application) */
      if(cconf->is_vip_by_header) {
        u->netstat[net].vip = 1;
      }
    }
    apr_global_mutex_unlock(u->lock);                 /* @CRT10 */
  }
  if(cconf->sconf->max_conn != -1) {
    apr_global_mutex_lock(cconf->sconf->act->lock);   /* @CRT3 */
    if(cconf->sconf->act->c->connections) cconf->sconf->act->c->connections--;
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
static int qos_process_connection(conn_rec *c) {
  qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(c->conn_config, &qos_module);
  int vip = 0;
  if(cconf == NULL) {
    int client_control = DECLINED;
    int connections;
    int net_connections;
    int current;
    char *msg = NULL;
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(c->base_server->module_config,
                                                                  &qos_module);
    qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
    cconf = apr_pcalloc(c->pool, sizeof(qs_conn_ctx));
    cconf->c = c;
    cconf->evmsg = NULL;
    cconf->sconf = sconf;
    cconf->is_vip = 0;
    cconf->is_vip_by_header = 0;
    cconf->has_lowrate = 0;
    ap_set_module_config(c->conn_config, &qos_module, cconf);
    apr_pool_cleanup_register(c->pool, cconf, qos_cleanup_conn, apr_pool_cleanup_null);

    /* control timeout */
    qos_timeout_pc(c, sconf);

    /* packet rate */
    if(sconf->qos_cc_prefer_limit) {
      qos_pktrate_pc(c, sconf);
    }

    /* evaluates client ip */
    if((sconf->max_conn_per_ip != -1) ||
       sconf->has_qos_cc) {
      cconf->ip = inet_addr(cconf->c->remote_ip); /* v4 */
#ifdef QS_INTERNAL_TEST
      /* use one of the predefined ip addresses */
      if(cconf->sconf->enable_testip) {
        char *testid = apr_psprintf(c->pool, "%d", rand()%(QS_SIM_IP_LEN-1));
        const char *testip = apr_table_get(cconf->sconf->testip, testid);
        cconf->ip = inet_addr(testip);
      }
#endif
    }

    /* ------------------------------------------------------------
     * update data
     */
    /* client control */
    client_control = qos_cc_pc_filter(cconf, u, &msg);
    /* vhost connections */
    if(sconf->max_conn != -1) {
      apr_global_mutex_lock(cconf->sconf->act->lock);  /* @CRT4 */
      cconf->sconf->act->c->connections++;
      connections = cconf->sconf->act->c->connections; /* @CRT4 */
      apr_global_mutex_unlock(cconf->sconf->act->lock);
    }
    /* single source ip */
    if(sconf->max_conn_per_ip != -1) {
      current = qos_add_ip(c->pool, cconf);
    }
    /* preferred net */
    if(sconf->net_prefer) {
      apr_global_mutex_lock(u->lock);                  /* @CRT9 */
      u->connections++;
      net_connections = u->connections;
      apr_global_mutex_unlock(u->lock);                /* @CRT9 */
    }

    /* check for vip (by ip) */
    if(apr_table_elts(sconf->exclude_ip)->nelts > 0) {
      int i;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->exclude_ip)->elts;
      for(i = 0; i < apr_table_elts(sconf->exclude_ip)->nelts; i++) {
        if(entry[i].val[0] == 'r') {
          if(strncmp(entry[i].key, cconf->c->remote_ip, strlen(entry[i].key)) == 0) {
            vip = 1;
            /* propagate vip to connection */
            cconf->is_vip = vip;
            cconf->evmsg = apr_pstrcat(c->pool, "S;", cconf->evmsg, NULL);
          }
        } else {
          if(strcmp(entry[i].key, cconf->c->remote_ip) == 0) {
            vip = 1;
            /* propagate vip to connection */
            cconf->is_vip = vip;
            cconf->evmsg = apr_pstrcat(c->pool, "S;", cconf->evmsg, NULL);
          }
        }
      }
    }

    /* ------------------------------------------------------------
     * enforce rules
     */
    /* client control */
    if((client_control != DECLINED) && !vip) {
      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                   "%s",
                   msg == NULL ? "-" : msg);
      c->keepalive = AP_CONN_CLOSE;
      return qos_return_error(c);
    }
    /* vhost connections */
    if((sconf->max_conn != -1) && !vip) {
      if(connections > sconf->max_conn) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                     QOS_LOG_PFX(030)"access denied, QS_SrvMaxConn rule: max=%d,"
                     " concurrent connections=%d,"
                     " c=%s",
                     sconf->max_conn, connections,
                     c->remote_ip == NULL ? "-" : c->remote_ip);
        c->keepalive = AP_CONN_CLOSE;
        return qos_return_error(c);
      }
    }
    /* single source ip */
    if((sconf->max_conn_per_ip != -1) && !vip) {
      if(current > sconf->max_conn_per_ip) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                     QOS_LOG_PFX(031)"access denied, QS_SrvMaxConnPerIP rule: max=%d,"
                     " concurrent connections=%d,"
                     " c=%s",
                     sconf->max_conn_per_ip, current,
                     c->remote_ip == NULL ? "-" : c->remote_ip);
        c->keepalive = AP_CONN_CLOSE;
        return qos_return_error(c);
      }
    }
    /* preferred net */
    if(sconf->net_prefer && !vip) {
      if(net_connections > sconf->net_prefer_limit) {
        /* enforce */
        int net = qos_get_net(cconf);
        if(u->netstat[net].vip == 0) {
          /* not a vip net */
          ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                       QOS_LOG_PFX(033)"access denied, QS_SrvPreferNet rule: max=%d,"
                       " concurrent connections=%d,"
                       " c=%s",
                       sconf->net_prefer_limit, net_connections,
                       c->remote_ip == NULL ? "-" : c->remote_ip);
          c->keepalive = AP_CONN_CLOSE;
          return qos_return_error(c);
        }
      }
    }
  }
  return DECLINED;
}

/**
 * pre connection, constructs the connection ctx (stores socket ref)
 */
static int qos_pre_connection(conn_rec *c, void *skt) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(c->base_server->module_config,
                                                                &qos_module);
  if(sconf && (sconf->req_rate != -1)) {
    qos_ifctx_t *inctx = qos_create_ifctx(c);
    inctx->client_socket = skt;
    ap_add_input_filter("qos-in-filter", inctx, NULL, c);
  }
  return DECLINED;
}

/**
 * all headers has been read, end/update connection level filters
 */
static int qos_post_read_request(request_rec * r) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->connection->base_server->module_config,
                                                                &qos_module);
  qos_ifctx_t *inctx = NULL;
  if(sconf && (sconf->req_rate != -1)) {
    inctx = qos_get_ifctx(r->connection->input_filters);
    if(inctx) {
      const char *te = apr_table_get(r->headers_in, "Transfer-Encoding");
      inctx->r = r;
      if(r->read_chunked || (te && (strcasecmp(te, "chunked") == 0))) {
        ap_add_input_filter("qos-in-filter2", inctx, r, r->connection);
        inctx->status = QS_CONN_STATE_CHUNKED;
      } else {
        const char *cl = apr_table_get(r->headers_in, "Content-Length");
        if(cl == NULL) {
          inctx->status = QS_CONN_STATE_END;
#if APR_HAS_THREADS
          apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT26 */
          apr_table_unset(sconf->inctx_t->table,
                          apr_psprintf(inctx->c->pool, "%d", (int)inctx));
          apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT26 */
#endif
        } else {
          if(APR_SUCCESS == apr_strtoff(&inctx->cl_val, cl, NULL, 0)) {
            ap_add_input_filter("qos-in-filter2", inctx, r, r->connection);
            inctx->status = QS_CONN_STATE_BODY;
          } else {
          }
        }
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
    char *msg;
    char *uid;
    int req_per_sec_block = 0;
    int status;
    qs_acentry_t *e;
    qs_acentry_t *e_cond;
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_module);
    qos_dir_config *dconf = (qos_dir_config*)ap_get_module_config(r->per_dir_config,
                                                                  &qos_module);
    qs_req_ctx *rctx = NULL;

    /* 
     * QS_Permit* / QS_Deny* enforcement
     */
    status = qos_hp_filter(r, sconf, dconf);
    if(status != DECLINED) {
      return status;
    }

    /*
     * QS_RequestHeaderFilter enforcement
     */
    status = qos_hp_header_filter(r, sconf, dconf);
    if(status != DECLINED) {
      return status;
    }

    /* 
     * Dynamic keep alive
     */
    qos_hp_keepalive(r);

    /*
     * VIP control
     */
    if(sconf->header_name) {
      rctx = qos_rctx_config_get(r);
      rctx->is_vip = qos_is_vip(r, sconf);
      if(rctx->is_vip) {
        qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config,
                                                                &qos_module);
        if(cconf) cconf->is_vip = 1;
      }
    }

    /*
     * additional variables
     */
    qos_setenvif(r, sconf);

    /*
     * QS_EventPerSecLimit
     */
    req_per_sec_block = qos_hp_event_count(r);

    /*
     * client control
     */
    if(qos_hp_cc(r, sconf, &msg, &uid) != DECLINED) {
      const char *error_page = sconf->error_page;
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    "%s, id=%s", msg == NULL ? "-" : msg,
                    qos_unique_id(r, uid));
      if(!rctx) {
        rctx = qos_rctx_config_get(r);
      }
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
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    /* get rule with conditional enforcement */
    e_cond = qos_getcondrule_byregex(r, sconf);
    /* 1st prio has "Match" rule */
    e = qos_getrule_byregex(r, sconf);
    /* 2th prio has "URL" rule */
    if(!e) e = qos_getrule_bylocation(r, sconf);
    if(e || e_cond) {
      const char *error_page = sconf->error_page;
      if(!rctx) {
        rctx = qos_rctx_config_get(r);
      }
      if(r->subprocess_env) {
        const char *v = apr_table_get(r->subprocess_env, "QS_ErrorPage");
        if(v) {
          error_page = v;
        }
      }
      rctx->entry_cond = e_cond;
      rctx->entry = e;
      if(e || e_cond) {
        apr_global_mutex_lock(e->lock);   /* @CRT5 */
        if(e_cond) {
          e_cond->counter++;
        }
        if(e) {
          e->counter++;
          if(e->req_per_sec_block_rate > req_per_sec_block) {
            /* update req_per_sec_block if event restriction has returned worse block rate */
            req_per_sec_block = e->req_per_sec_block_rate;
          }
        }
        apr_global_mutex_unlock(e->lock); /* @CRT5 */
      }
        
      if(e) {
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
                          QOS_LOG_PFX(010)"access denied, QS_LocRequestLimit* rule: %s(%d),"
                          " concurrent requests=%d,"
                          " c=%s, id=%s",
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
            /* don't wait more than once */
            req_per_sec_block = 0;
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
      if(e_cond) {
        /*
         * QS_CondLocRequestLimitMatch
         */
        if(e_cond->limit && (e_cond->counter > e_cond->limit)) {
          /* check condition */
          const char *condition = apr_table_get(r->subprocess_env, "QS_Cond");
          if(condition) {
            if(ap_regexec(e_cond->condition, condition, 0, NULL, 0) == 0) {
              /* vip session has no limitation */
              if(rctx->is_vip) {
                rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
              } else {
                /* std user */
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                              QOS_LOG_PFX(011)"access denied, QS_CondLocRequestLimitMatch"
                              " rule: %s(%d),"
                              " concurrent requests=%d,"
                              " c=%s, id=%s",
                              e_cond->url, e_cond->limit, e_cond->counter,
                              r->connection->remote_ip == NULL ? "-" : r->connection->remote_ip,
                              qos_unique_id(r, "011"));
                rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
                if(error_page) {
                  qos_error_response(r, error_page);
                  return DONE;
                }
                return HTTP_INTERNAL_SERVER_ERROR;
              }
            }
          }
        }
      }
    }

    /*
     * QS_EventPerSecLimit
     */
    if(req_per_sec_block) {
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      int sec = req_per_sec_block / 1000;
      int nsec = req_per_sec_block % 1000;
      struct timespec delay;
      rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
      delay.tv_sec  = sec;
      delay.tv_nsec = nsec * 1000000;
      nanosleep(&delay,NULL);
    }

  }
  return DECLINED;
}

static apr_status_t qos_in_filter2(ap_filter_t *f, apr_bucket_brigade *bb,
                                  ap_input_mode_t mode, apr_read_type_e block,
                                  apr_off_t nbytes) {
  qos_ifctx_t *inctx = f->ctx;
  apr_status_t rv = ap_get_brigade(f->next, bb, mode, block, nbytes);
  if((rv == APR_SUCCESS) && APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                  &qos_module);
    ap_remove_input_filter(f);
#if APR_HAS_THREADS
    apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT28 */
    apr_table_unset(sconf->inctx_t->table,
                    apr_psprintf(inctx->c->pool, "%d", (int)inctx));
    apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT28 */
#endif
  }
  return rv;
}

/**
 * input filter, used to log timeout event, mark slow clients,
 * and to calculate packet rate
 */
static apr_status_t qos_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                  ap_input_mode_t mode, apr_read_type_e block,
                                  apr_off_t nbytes) {
  apr_status_t rv;
  qos_ifctx_t *inctx = f->ctx;
  apr_size_t bytes = 0;

  rv = ap_get_brigade(f->next, bb, mode, block, nbytes);
  if(rv == APR_SUCCESS) {
    if(inctx->lowrate != -1) {
      bytes = qos_packet_rate(inctx, bb);
    }
  }
  if(inctx->status == QS_CONN_STATE_KEEP) {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                  &qos_module);
    inctx->status = QS_CONN_STATE_HEAD;
    inctx->time = time(NULL);
    inctx->nbytes = 0;
#if APR_HAS_THREADS
    if(sconf->inctx_t && !sconf->inctx_t->exit) {
      apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT23 */
      apr_table_setn(sconf->inctx_t->table,
                     apr_psprintf(inctx->c->pool, "%d", (int)inctx),
                     (char *)inctx);
      apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT23 */
    }
#endif
  }
  if(rv != APR_SUCCESS) {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                  &qos_module);
    inctx->status = QS_CONN_STATE_END;
    inctx->time = 0;
    inctx->nbytes = 0;
#if APR_HAS_THREADS
    if(sconf->inctx_t && !sconf->inctx_t->exit) {
      apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT24 */
      apr_table_unset(sconf->inctx_t->table,
                      apr_psprintf(inctx->c->pool, "%d", (int)inctx));
      apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT24 */
    }
#endif
  }
  if(inctx->status > QS_CONN_STATE_NEW) {
    if(rv == APR_SUCCESS) {
      if(bytes == 0) {
        apr_bucket *b;
        for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
          bytes = bytes + b->length;
        }
      }
      inctx->nbytes = inctx->nbytes + bytes;
      if(inctx->status == QS_CONN_STATE_BODY) {
        if(inctx->cl_val >= bytes) {
          inctx->cl_val = inctx->cl_val - bytes;
        }
        if(inctx->cl_val == 0) {
          qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                        &qos_module);
#if APR_HAS_THREADS
          apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT27 */
          apr_table_unset(sconf->inctx_t->table,
                          apr_psprintf(inctx->c->pool, "%d", (int)inctx));
          apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT27 */
#endif
        }
      }
    }
    if(rv == APR_TIMEUP) {
      qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                    &qos_module);
      /* mark clients causing a timeout */
      if(sconf) {
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
        qos_s_entry_t **e = NULL;
        qos_s_entry_t new;
        apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT18 */
        new.ip = inet_addr(inctx->c->remote_ip); /* v4 */
        e = qos_cc_get0(u->qos_cc, &new);
        if(!e) {
          e = qos_cc_set(u->qos_cc, &new, time(NULL));
        }
        (*e)->lowrate = time(NULL);
        apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT18 */
      }
      inctx->lowrate = QS_PKT_RATE_TH + 1;
    }
  }
  return rv;
}

/**
 * output filter adds response delay
 */
static apr_status_t qos_out_filter_delay(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  if(rctx->entry) {
    if(rctx->is_vip) {
      rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
    } else {
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
  qos_setenvresheader(r, sconf);
  if(sconf->ip_header_name) {
    const char *ctrl_h = apr_table_get(r->headers_out, sconf->ip_header_name);
    if(ctrl_h) {
      qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config,
                                                              &qos_module);
      if(cconf) {
        cconf->is_vip = 1;
        cconf->is_vip_by_header = 1;
      }
      apr_table_unset(r->headers_out, sconf->ip_header_name);
    }
  }
  if(sconf->header_name) {
    /* got a vip header: create new session (if non exists) */
    const char *ctrl_h = apr_table_get(r->headers_out, sconf->header_name);
    if(ctrl_h && !apr_table_get(r->notes, QS_REC_COOKIE)) {
      qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config,
                                                              &qos_module);
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      qos_set_session(r, sconf);
      rctx->evmsg = apr_pstrcat(r->pool, "V;", rctx->evmsg, NULL);
      if(cconf) {
        cconf->is_vip = 1;
        cconf->is_vip_by_header = 1;
      }
      apr_table_unset(r->headers_out, sconf->header_name);
      apr_table_set(r->notes, QS_REC_COOKIE, "");
    }
  }
  if(sconf->vip_user && r->user) {
    if(!apr_table_get(r->notes, QS_REC_COOKIE)) {
      qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config,
                                                              &qos_module);
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      qos_set_session(r, sconf);
      rctx->evmsg = apr_pstrcat(r->pool, "V;", rctx->evmsg, NULL);
      if(cconf) {
        cconf->is_vip = 1;
        cconf->is_vip_by_header = 1;
      }
      apr_table_set(r->notes, QS_REC_COOKIE, "");
    }
  }
  if(sconf->vip_ip_user && r->user) {
    qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config,
                                                            &qos_module);
    if(cconf) {
      cconf->is_vip = 1;
      cconf->is_vip_by_header = 1;
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
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  qs_acentry_t *e = rctx->entry;
  qs_acentry_t *e_cond = rctx->entry_cond;
  qs_conn_ctx *cconf = (qs_conn_ctx*)ap_get_module_config(r->connection->conn_config, &qos_module);
  time_t now = 0;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  qos_setenvstatus(r, sconf);
  qos_setenvif(r, sconf);
  qos_logger_cc(r, sconf);
  if(cconf && cconf->evmsg) {
    rctx->evmsg = apr_pstrcat(r->pool, cconf->evmsg, rctx->evmsg, NULL);
  }
  qos_lg_event_update(r, &now);
  if(e || e_cond) {
    char *h = apr_psprintf(r->pool, "%d", e->counter);
    if(!now) {
      now = apr_time_sec(r->request_time);
    }
    apr_global_mutex_lock(e->lock);   /* @CRT6 */
    if(e_cond) {
      if(e_cond->counter) e_cond->counter--;
    }
    if(e) {
      if(e->counter) e->counter--;
      e->req++;
      e->bytes = e->bytes + r->bytes_sent;
      if(now > e->interval + 10) {
        e->req_per_sec = e->req / (now - e->interval);
        e->req = 0;
        e->kbytes_per_sec = e->bytes / (now - e->interval) / 1024;
        e->bytes = 0;
        e->interval = now;
        if(e->req_per_sec_limit) {
          qos_cal_req_sec(r, e);
        }
        if(e->kbytes_per_sec_limit) {
          if(e->kbytes_per_sec > e->kbytes_per_sec_limit) {
            int factor = ((e->kbytes_per_sec * 100) / e->kbytes_per_sec_limit) - 100;
            e->kbytes_per_sec_block_rate = e->kbytes_per_sec_block_rate + factor;
            if(e->kbytes_per_sec_block_rate > QS_MAX_DELAY) {
              e->kbytes_per_sec_block_rate = QS_MAX_DELAY;
            }
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          QOS_LOG_PFX(052)"byte rate limit, rule: %s(%ld), kbytes/sec=%ld,"
                          " delay=%dms%s",
                          e->url, e->kbytes_per_sec_limit,
                          e->kbytes_per_sec, e->kbytes_per_sec_block_rate,
                          e->kbytes_per_sec_block_rate == QS_MAX_DELAY ? " (max)" : "");
          } else if(e->kbytes_per_sec_block_rate > 0) {
            if(e->kbytes_per_sec_block_rate < 50) {
              e->kbytes_per_sec_block_rate = 0;
            } else {
              int factor = e->kbytes_per_sec_block_rate / 6;
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
    }
    apr_global_mutex_unlock(e->lock); /* @CRT6 */
    /* allow logging of the current location usage */
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
  qos_user_t *u = qos_get_user_conf(sconf->act->ppool, 0);
  qos_ifctx_list_t *inctx_t = NULL;
#if APR_HAS_THREADS
  if(sconf->req_rate != -1) {
    inctx_t = apr_pcalloc(p, sizeof(qos_ifctx_list_t));
    inctx_t->exit = 0;
    inctx_t->table = apr_table_make(p, 64);
    sconf->inctx_t = inctx_t;
    if(apr_thread_mutex_create(&sconf->inctx_t->lock, APR_THREAD_MUTEX_DEFAULT, p) != APR_SUCCESS) {
      qos_disable_req_rate(bs, "create mutex");
    } else {
      apr_threadattr_t *tattr;
      if(apr_threadattr_create(&tattr, p) != APR_SUCCESS) {
        qos_disable_req_rate(bs, "create thread attr");
      } else {
        if(apr_thread_create(&sconf->inctx_t->thread, tattr,
                             qos_req_rate_thread, bs, p) != APR_SUCCESS) {
          qos_disable_req_rate(bs, "create thread");
        } else {
          server_rec *sn = bs->next;
          apr_pool_cleanup_register(p, bs, qos_cleanup_req_rate_thread, apr_pool_cleanup_null);
          while(sn) {
            qos_srv_config *sc = (qos_srv_config*)ap_get_module_config(sn->module_config, &qos_module);
            sc->inctx_t = inctx_t;
            sn = sn->next;
          }
        }
      }
    }
  }
#endif
  if(sconf->net_prefer) {
    apr_global_mutex_child_init(&u->lock, u->lock_file, p);
  }
  if(sconf->has_qos_cc) {
    apr_global_mutex_child_init(&u->qos_cc->lock, u->qos_cc->lock_file, p);
  }
  if(!sconf->act->child_init) {
    sconf->act->child_init = 1;
    /* propagate mutex to child process (required for certaing platforms) */
    apr_global_mutex_child_init(&sconf->act->lock, sconf->act->lock_file, p);
    while(s) {
      sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
      if(sconf->is_virtual) {
        apr_global_mutex_child_init(&sconf->act->lock, sconf->act->lock_file, p);
        e = sconf->act->entry;
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
  qos_user_t *u;
  int net_prefer = 0;
  int net_prefer_limit = 0;
  int cc_net_prefer_limit = 0;
  ap_directive_t *pdir;
  for (pdir = ap_conftree; pdir != NULL; pdir = pdir->next) {
    if(strcasecmp(pdir->directive, "MaxClients") == 0) {
      net_prefer = atoi(pdir->args);
    }
  }
  if(net_prefer <= 1) {
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                 QOS_LOG_PFX(007)"could not determine MaxClients");
  }
  net_prefer_limit = net_prefer * 80 / 100;
  cc_net_prefer_limit = net_prefer * sconf->qos_cc_prefer / 100;
  if(sconf->net_prefer && net_prefer) {
    sconf->net_prefer = net_prefer;
    sconf->net_prefer_limit = net_prefer_limit;
  } else {
    sconf->net_prefer = 0;
    sconf->net_prefer_limit = 0;
  }
  if(sconf->qos_cc_prefer && net_prefer) {
    sconf->qos_cc_prefer = net_prefer;
    sconf->qos_cc_prefer_limit = cc_net_prefer_limit;
  } else {
    sconf->qos_cc_prefer = 0;
    sconf->qos_cc_prefer_limit = 0;
  }
  u = qos_get_user_conf(bs->process->pool, sconf->net_prefer);
  if(u == NULL) return !OK;
  u->server_start++;
  sconf->base_server = bs;
  sconf->act->timeout = apr_time_sec(bs->timeout);
  if(sconf->act->timeout == 0) sconf->act->timeout = 300;
  if(qos_init_shm(bs, sconf->act, sconf->location_t) != APR_SUCCESS) {
    return !OK;
  }
  apr_pool_cleanup_register(sconf->pool, sconf->act,
                            qos_cleanup_shm, apr_pool_cleanup_null);

  if(u->server_start == 2) {
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->hfilter_table)->elts;
    for(i = 0; i < apr_table_elts(sconf->hfilter_table)->nelts; i++) {
      qos_fhlt_r_t *he = (qos_fhlt_r_t *)entry[i].val;
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, bs, 
                   QOS_LOG_PFX(000)"header filter rule (%s) %s: %s",
                   he->action == QS_FLT_ACTION_DROP ? "drop" : "deny", entry[i].key, he->text);
    }
  }
  if(sconf->has_qos_cc && !u->qos_cc) {
    u->qos_cc = qos_cc_new(bs->process->pool, sconf->qos_cc_size);
    if(u->qos_cc == NULL) {
      return !OK;
    }
  }
  while(s) {
    qos_srv_config *ssconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    ssconf->base_server = bs;
    ssconf->act->timeout = apr_time_sec(s->timeout);
    ssconf->net_prefer = sconf->net_prefer;
    ssconf->net_prefer_limit = sconf->net_prefer_limit;
    ssconf->qos_cc_prefer = sconf->qos_cc_prefer;
    ssconf->qos_cc_prefer_limit = sconf->qos_cc_prefer_limit;
    if(ssconf->act->timeout == 0) {
      ssconf->act->timeout = 300;
    }
    if(ssconf->is_virtual) {
      if(qos_init_shm(s, ssconf->act, ssconf->location_t) != APR_SUCCESS) {
        return !OK;
      }
      apr_pool_cleanup_register(ssconf->pool, ssconf->act,
                                qos_cleanup_shm, apr_pool_cleanup_null);
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
 * mod_qos
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
          background-color: rgb(250,248,246);\n\
          color: black;\n\
          font-family: arial, helvetica, verdana, sans-serif;\n\
   }\n\
  .btable{\n\
          background-color: white;\n\
          border: 1px solid; padding: 0px;\n\
          margin: 6px; width: 920px;\n\
          font-weight: normal;\n\
          border-collapse: collapse;\n\
  }\n\
  .rowts {\n\
          background-color: rgb(165,150,158);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .rowt {\n\
          background-color: rgb(220,210,215);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .rows {\n\
          background-color: rgb(235,228,230);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .row  {\n\
          background-color: white;\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .row2  {\n\
          background-color: rgb(240,233,235);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .rowe {\n\
          background-color: rgb(200,186,190);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .rowe2 {\n\
          background-color: rgb(185,175,177);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  form      { display: inline; }\n", r);
    ap_rputs("-->\n", r);
    ap_rputs("</style>\n", r);
    ap_rputs("</head><body>\n", r);
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
 * merges dir config, inheritoff disables merge of rfilter_table.
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
  sconf->setenvif_t = apr_table_make(sconf->pool, 1);
  sconf->setenvstatus_t = apr_table_make(sconf->pool, 1);
  sconf->setenvresheader_t = apr_table_make(sconf->pool, 1);
  sconf->setenvresheadermatch_t = apr_table_make(sconf->pool, 1);
  sconf->error_page = NULL;
  sconf->req_rate = -1;
  sconf->act = (qs_actable_t *)apr_pcalloc(act_pool, sizeof(qs_actable_t));
  sconf->act->pool = act_pool;
  sconf->act->ppool = s->process->pool;
  sconf->act->generation = ap_my_generation;
  sconf->act->m_file = NULL;
  sconf->act->child_init = 0;
  sconf->act->timeout = apr_time_sec(s->timeout);
  sconf->act->has_events = 0;
  sconf->act->lock_file = apr_psprintf(sconf->act->pool, "%s.mod_qos",
                                       ap_server_root_relative(sconf->act->pool, tmpnam(NULL)));
  rv = apr_global_mutex_create(&sconf->act->lock, sconf->act->lock_file,
                               APR_LOCK_DEFAULT, sconf->act->pool);
  if (rv != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(rv, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                 QOS_LOG_PFX(004)"could not create a-mutex: %s", buf);
    exit(1);
  }
  sconf->is_virtual = s->is_virtual;
  sconf->cookie_name = apr_pstrdup(sconf->pool, QOS_COOKIE_NAME);
  sconf->cookie_path = apr_pstrdup(sconf->pool, "/");
  sconf->max_age = atoi(QOS_MAX_AGE);
  sconf->header_name = NULL;
  sconf->ip_header_name = NULL;
  sconf->vip_user = 0;
  sconf->vip_ip_user = 0;
  sconf->max_conn = -1;
  sconf->max_conn_close = -1;
  sconf->max_conn_per_ip = -1;
  sconf->exclude_ip = apr_table_make(sconf->pool, 2);
  sconf->hfilter_table = apr_table_make(p, 1);
  sconf->net_prefer = 0;
  sconf->has_qos_cc = 0;
  sconf->qos_cc_size = 50000;
  sconf->qos_cc_prefer = 0;
  sconf->qos_cc_prefer_limit = 0;
  sconf->qos_cc_event = 0;
  sconf->qos_cc_block = 0;
  sconf->qos_cc_block_time = 600;
  if(!s->is_virtual) {
    char *msg = qos_load_headerfilter(p, sconf->hfilter_table);
    if(msg) {
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                   QOS_LOG_PFX(006)"could not compile header filter rules: %s", msg);
      exit(1);
    }
  }

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
 * but: header filter table and connection timeouts are always used from
 * the base server
 */
static void *qos_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  qos_srv_config *b = (qos_srv_config *)basev;
  qos_srv_config *o = (qos_srv_config *)addv;
  /* base table may contain custom rules */
  o->hfilter_table = b->hfilter_table;
  o->net_prefer = b->net_prefer;
  o->has_qos_cc = b->has_qos_cc;
  o->qos_cc_size = b->qos_cc_size;
  o->qos_cc_prefer = b->qos_cc_prefer;
  o->qos_cc_prefer_limit = b->qos_cc_prefer_limit;
  o->qos_cc_event = b->qos_cc_event;
  o->qos_cc_block = b->qos_cc_block;
  o->qos_cc_block_time = b->qos_cc_block_time;
  /* location rules or connection limit controls conf merger (see index.html) */
  if((apr_table_elts(o->location_t)->nelts > 0) ||
     (o->max_conn != -1) ||
     (o->max_conn_per_ip != -1)) {
    o->req_rate = b->req_rate;
#ifdef QS_INTERNAL_TEST
    o->enable_testip = b->enable_testip;
#endif
    return o;
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
  rule->event = NULL;
  rule->regex = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, loc), (char *)rule);
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
  rule->event = NULL;
  rule->regex = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, loc), (char *)rule);
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
  rule->event = NULL;
  rule->regex = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, loc), (char *)rule);
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
  rule->event = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, match), (char *)rule);
  return NULL;
}

/**
 * defines the maximum of concurrent requests matching the specified
 * request line pattern
 */
const char *qos_cond_match_con_cmd(cmd_parms *cmd, void *dcfg, const char *match,
                                   const char *limit, const char *pattern) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  rule->url = apr_pstrdup(cmd->pool, match);
  rule->limit = atoi(limit);
  if(rule->limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
  rule->condition = ap_pregcomp(cmd->pool, pattern, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
  rule->condition = ap_pregcomp(cmd->pool, pattern, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  if(rule->condition == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, pattern);
  }
  rule->event = NULL;
  apr_table_setn(sconf->location_t, apr_pstrcat(cmd->pool, match, "##conditional##", NULL), (char *)rule);
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
  rule->event = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, match), (char *)rule);
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
  rule->event = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, match), (char *)rule);
  return NULL;
}

/**
 * sets the default limitation of cuncurrent requests
 */
const char *qos_loc_con_def_cmd(cmd_parms *cmd, void *dcfg, const char *limit) {
  return qos_loc_con_cmd(cmd, dcfg, "/", limit);
}

/**
 * defines the maximum requests/sec for the matching variable.
 */
const char *qos_event_rs_cmd(cmd_parms *cmd, void *dcfg, const char *event, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  rule->url = apr_pstrcat(cmd->pool, "var=[", event, "]", NULL);
  rule->req_per_sec_limit = atol(limit);
  if(rule->req_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  rule->event = apr_pstrdup(cmd->pool, event);
  rule->regex = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, rule->url, (char *)rule);
  return NULL;
}

const char *qos_event_setenvstatus_cmd(cmd_parms *cmd, void *dcfg, const char *rc, const char *var) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  apr_table_set(sconf->setenvstatus_t, rc, var);
  return NULL;
}

const char *qos_event_setenvresheader_cmd(cmd_parms *cmd, void *dcfg, const char *hdr, const char *action) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  apr_table_set(sconf->setenvresheader_t, hdr, action == NULL ? "" : action);
  return NULL;
}

const char *qos_event_setenvresheadermatch_cmd(cmd_parms *cmd, void *dcfg, const char *hdr,
                                               const char *pcres) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *errptr = NULL;
  int erroffset;
  pcre *pr = pcre_compile(pcres, PCRE_DOTALL | PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pr == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        erroffset, errptr);
  }
  apr_pool_cleanup_register(cmd->pool, pr, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  apr_table_setn(sconf->setenvresheadermatch_t, apr_pstrdup(cmd->pool, hdr), (char *)pr);
  return NULL;
}

const char *qos_event_setenvif_cmd(cmd_parms *cmd, void *dcfg, const char *v1, const char *v2,
                                   const char *a3) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qos_setenvif_t *setenvif = apr_pcalloc(cmd->pool, sizeof(qos_setenvif_t));
  setenvif->variable1 = apr_pstrdup(cmd->pool, v1);
  setenvif->variable2 = apr_pstrdup(cmd->pool, v2);
  setenvif->name = apr_pstrdup(cmd->pool, a3);
  setenvif->value = strchr(setenvif->name, '=');
  if(setenvif->value == NULL) {
    return apr_psprintf(cmd->pool, "%s: new variable must have the format <name>=<value>",
                        cmd->directive->directive);
  }
  setenvif->value[0] = '\0';
  setenvif->value++;
  apr_table_setn(sconf->setenvif_t, apr_pstrcat(cmd->pool, v1, v2, a3, NULL), (char *)setenvif);
  return NULL;
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

const char *qos_ip_header_name_cmd(cmd_parms *cmd, void *dcfg, const char *name) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->ip_header_name = apr_pstrdup(cmd->pool, name);
  return NULL;
}

const char *qos_vip_u_cmd(cmd_parms *cmd, void *dcfg) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->vip_user = 1;
  return NULL;
}

const char *qos_vip_ip_u_cmd(cmd_parms *cmd, void *dcfg) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->vip_ip_user = 1;
  return NULL;
}

/**
 * prefer clients from known networks
 */
const char *qos_pref_conn_cmd(cmd_parms *cmd, void *dcfg) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->net_prefer = 1;
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

const char *qos_req_rate_cmd(cmd_parms *cmd, void *dcfg, const char *sec) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->req_rate = atoi(sec);
  if(sconf->req_rate == 0) {
    return apr_psprintf(cmd->pool, "%s: request rate must be a numeric value >0", 
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
  dconf->headerfilter = flag;
  return NULL;
}

/* set custom header rules (global only) */
const char *qos_headerfilter_rule_cmd(cmd_parms *cmd, void *dcfg, const char *header,
                                      const char *rule, const char *action) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *errptr = NULL;
  int erroffset;
  qos_fhlt_r_t *he;
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  he = apr_pcalloc(cmd->pool, sizeof(qos_fhlt_r_t));
  he->text = apr_pstrdup(cmd->pool, rule);
  he->pcre = pcre_compile(rule, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(strcasecmp(action, "deny") == 0) {
    he->action = QS_FLT_ACTION_DENY;
  } else if(strcasecmp(action, "drop") == 0) {
    he->action = QS_FLT_ACTION_DROP;
  } else {
    return apr_psprintf(cmd->pool, "%s: incalid action %s",
                        cmd->directive->directive, action);
  }
  if(he->pcre == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre %s at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        rule,
                        erroffset, errptr);
  }
  apr_table_setn(sconf->hfilter_table, header, (char *)he);
  apr_pool_cleanup_register(cmd->pool, he->pcre, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  return NULL;
}

const char *qos_client_cmd(cmd_parms *cmd, void *dcfg, const char *arg1) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->qos_cc_size = atoi(arg1);
  if(sconf->qos_cc_size == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

#ifdef AP_TAKE_ARGV
const char *qos_client_pref_cmd(cmd_parms *cmd, void *dcfg, int argc, char *const argv[]) {
#else
const char *qos_client_pref_cmd(cmd_parms *cmd, void *dcfg) {
  int argc = 0;
  char *const argv = NULL;
#endif
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  sconf->qos_cc_prefer = 80;
  if(argc) {
    sconf->qos_cc_prefer = atoi(argv[0]);
  }
  if((sconf->qos_cc_prefer == 0) || (sconf->qos_cc_prefer > 99)) {
    return apr_psprintf(cmd->pool, "%s: percentage must be numeric value between 1 and 99",
                        cmd->directive->directive);
  }
  if(argc > 1) {
    return apr_psprintf(cmd->pool, "%s: command takes not more than one argument",
                        cmd->directive->directive);
  }
  return NULL;
}

const char *qos_client_block_cmd(cmd_parms *cmd, void *dcfg, const char *arg1,
                                 const char *arg2) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  sconf->qos_cc_block = atoi(arg1);
  if(sconf->qos_cc_block == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  if(arg2) {
    sconf->qos_cc_block_time = atoi(arg2);
  }
  if(sconf->qos_cc_block_time == 0) {
    return apr_psprintf(cmd->pool, "%s: time must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

const char *qos_client_event_cmd(cmd_parms *cmd, void *dcfg, const char *arg1) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  sconf->qos_cc_event = atoi(arg1);
  if(sconf->qos_cc_event == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
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
                "QS_LocKBytesPerSecLimit <location> <kbytes>, defined the allowed"
                " download bandwidth to the defined kbytes per second. Responses are"
                "slowed by adding a delay to each response (non-linear, bigger files"
                " get longer delay than smaller ones). This directive should be used"
                " in conjunction with QS_LocRequestLimit only."),
  AP_INIT_TAKE2("QS_LocRequestLimitMatch", qos_match_con_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestLimitMatch <regex> <number>, defines the number of"
                " concurrent requests to the uri (path and query) pattern."
                " Default is defined by the QS_LocRequestLimitDefault directive."),

  AP_INIT_TAKE3("QS_CondLocRequestLimitMatch", qos_cond_match_con_cmd, NULL,
                RSRC_CONF,
                "QS_CondLocRequestLimitMatch <regex> <number> <pattern>, defines the number of"
                " concurrent requests to the uri (path and query) regex."
                " Rule is only enforced of the QS_Cond variable matches the specified"
                " pattern (regex)."),
  AP_INIT_TAKE2("QS_LocRequestPerSecLimitMatch", qos_match_rs_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestPerSecLimitMatch <regex> <number>, defines the allowed"
                " number of requests per second to the uri (path and query) pattern."
                " Requests are limited by adding a delay to each requests."
                " This directive should be used in conjunction with"
                " QS_LocRequestLimitMatch only."),
  AP_INIT_TAKE2("QS_LocKBytesPerSecLimitMatch", qos_match_bs_cmd, NULL,
                RSRC_CONF,
                "QS_LocKBytesPerSecLimit <regex> <kbytes>, defined the allowed"
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
  AP_INIT_TAKE1("QS_VipIPHeaderName", qos_ip_header_name_cmd, NULL,
                RSRC_CONF,
                "QS_VipIPHeaderName <name>, defines the http header name which is"
                " used to signalize priviledged clients (IP addresses)."),
  AP_INIT_NO_ARGS("QS_VipUser", qos_vip_u_cmd, NULL,
                  RSRC_CONF,
                  "QS_VipUser, creates a VIP session for users"
                  " which has been authenticated by the Apache server."
                  " May be used in conjunction with the QS_ClientPrefer and"
                  "QS_SrvPreferNet directives too."),
  AP_INIT_NO_ARGS("QS_VipIpUser", qos_vip_ip_u_cmd, NULL,
                  RSRC_CONF,
                  "QS_VipIpUser, marks a source IP as VIP if the user"
                  " has been authenticated by the Apache server."
                  " May be used in conjunction with the QS_ClientPrefer and"
                  "QS_SrvPreferNet directives only."),
  /* connection limitations */
  AP_INIT_NO_ARGS("QS_SrvPreferNet", qos_pref_conn_cmd, NULL,
                  RSRC_CONF,
                  "QS_SrvPreferNet, prefers known networks when server has"
                  " less than 80% of free TCP connections. Preferred networks"
                  " have VIP clients, see QS_VipHeaderName directive. Netmask"
                  " is 255.255.240.0 (each net represents 4096 hosts)."
                  " Directive is allowed in global server context only."),
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
#if APR_HAS_THREADS
  AP_INIT_TAKE1("QS_SrvRequestRate", qos_req_rate_cmd, NULL,
                RSRC_CONF,
                "QS_SrvRequestRate <bytes per seconds>, defines the minumum upload"
                " bandwidth a client must generate (the bytes send by the client"
                " per seconds). This bandwidth is measured every five seconds"
                " while receiving request data (request line, header fields, or"
                " body). The client connection get closed if the client does not"
                " fulfill the required request data rate and the concerned IP address"
                " get marked in order to be handled with low priority (see"
                " the QS_ClientPrefer directive). No limitation is set by default."),
#endif
  /* event */
  AP_INIT_TAKE2("QS_EventPerSecLimit", qos_event_rs_cmd, NULL,
                RSRC_CONF,
                "QS_EventPerSecLimit <variable> <number>, defines the allowed"
                " number of requests, having the specified variable set,"
                " per second. Requests are limited"
                " by adding a delay to each requests."),
  AP_INIT_TAKE3("QS_SetEnvIf", qos_event_setenvif_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvIf [!]<variable1> [!]<variable1> <variable=value>,"
                " defines the new variable if variable1 AND variable2 are set."),
  AP_INIT_TAKE2("QS_SetEnvStatus", qos_event_setenvstatus_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvStatus <status code> <variable>, adds the defined"
                " request environment variable if the HTTP status code matches the"
                " the defined value."),
  AP_INIT_TAKE12("QS_SetEnvResHeader", qos_event_setenvresheader_cmd, NULL,
                 RSRC_CONF,
                 "QS_SetEnvResHeader <header name> [drop], adds the defined"
                 " HTTP response header to the request environment variables."
                 " Deletes the header if the action 'drop' has been specified."),
  AP_INIT_TAKE2("QS_SetEnvResHeaderMatch", qos_event_setenvresheadermatch_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvResHeaderMatch <header name> <regex>, adds the defined"
                " HTTP response header to the request environment variables"
                " if the specified regular expression (pcre) matches the header value."),
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
  AP_INIT_FLAG("QS_RequestHeaderFilter", qos_headerfilter_cmd, NULL,
               ACCESS_CONF,
               "QS_RequestHeaderFilter 'on'|'off', filters request headers by allowing"
               " only these headers which match the request header rules defined by"
               " mod_qos. Request headers which do not conform these definitions"
               " are either dropped or the whole request is denied. Custom"
               " request headers may be added by the QS_RequestHeaderFilterRule"
               " directive."),
  AP_INIT_TAKE3("QS_RequestHeaderFilterRule", qos_headerfilter_rule_cmd, NULL,
                RSRC_CONF,
                "QS_RequestHeaderFilterRule <header name> <pcre> 'drop'|'deny', used"
                " to add custom header filter rules which override the internal"
                " filter rules of mod_qos."
                " Directive is allowed in global server context only."),
  /* client control */
  AP_INIT_TAKE1("QS_ClientEntries", qos_client_cmd, NULL,
                RSRC_CONF,
                "QS_ClientEntries <number>, defines the number of individual"
                " clients managed by mod_qos. Default are 50000"
                " Directive is allowed in global server context only."),
#ifdef AP_TAKE_ARGV
  AP_INIT_TAKE_ARGV("QS_ClientPrefer", qos_client_pref_cmd, NULL,
#else
  AP_INIT_NO_ARGS("QS_ClientPrefer", qos_client_pref_cmd, NULL,
#endif
                    RSRC_CONF,
                    "QS_ClientPrefer [<percent>], prefers known VIP clients when server has"
                    " less than 80% of free TCP connections. Preferred clients"
                    " are VIP clients only, see QS_VipHeaderName directive."
                    " Directive is allowed in global server context only."),
  AP_INIT_TAKE12("QS_ClientEventBlockCount", qos_client_block_cmd, NULL,
                 RSRC_CONF,
                 "QS_ClientEventBlockCount <number> [<seconds>], defines the maximum number"
                 " of QS_Block allowed within the defined time (default are 10 minutes)."
                 " Directive is allowed in global server context only."),
  AP_INIT_TAKE1("QS_ClientEventPerSecLimit", qos_client_event_cmd, NULL,
                RSRC_CONF,
                "QS_ClientEventPerSecLimit <number>, defines the number"
                " events pro seconds on a per client (source IP) basis."
                " Events are identified by requests having the"
                " QS_Event variable set."
                " Directive is allowed in global server context only."),
#ifdef QS_INTERNAL_TEST
  AP_INIT_FLAG("QS_EnableInternalIPSimulation", qos_disable_int_ip_cmd, NULL,
               RSRC_CONF,
               ""),
#endif
  { NULL }
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
  ap_register_input_filter("qos-in-filter2", qos_in_filter2, NULL, AP_FTYPE_RESOURCE);
  ap_register_output_filter("qos-out-filter", qos_out_filter, NULL, AP_FTYPE_RESOURCE);
  ap_register_output_filter("qos-out-filter-delay", qos_out_filter_delay, NULL, AP_FTYPE_RESOURCE);
  ap_hook_insert_filter(qos_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
  //ap_hook_insert_error_filter(qos_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);

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
