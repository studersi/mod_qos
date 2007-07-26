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
 * This release features the following directives:
 * - QS_LocRequestLimitMatch:
 *   Limits the number of concurrent requests matching a
 *   regular expression.
 * - QS_LocRequestLimit/QS_LocRequestLimitDefault:
 *   Limits the number of concurrent requests for a location.
 * - QS_ErrorPage:
 *   Customizable error page for denied requests.
 * - QS_VipHeaderName:
 *   Defines a response header which marks a VIP. VIP users have
 *   no access restrictions.
 * - QS_SessionTimeout/QS_SessionCookieName/QS_SessionCookiePath:
 *   Session is stored in cookie with several attributes.
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

static const char revision[] = "$Id: mod_qos.c,v 2.3 2007-07-26 15:10:16 pbuchbinder Exp $";

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

/************************************************************************
 * defines
 ***********************************************************************/
#define QOS_LOG_PFX "mod_qos: "
#define QOS_RAN 10
#define QOS_MAGIC_LEN 8
#define QOS_MAX_AGE "3600"
#define QOS_COOKIE_NAME "MODQOS"
static char qs_magic[QOS_MAGIC_LEN] = "qsmagic";

/************************************************************************
 * structures
 ***********************************************************************/

/**
 * session cookie
 */
typedef struct {
  unsigned char ran[QOS_RAN];
  char magic[QOS_MAGIC_LEN];
  time_t time;
} qos_session_t;

/** 
 * access table entry
 */
typedef struct qs_acentry_st {
  int id;
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
  char *lock_file;
  char *url;
} qs_acentry_t;

/**
 * access table (act)
 */
typedef struct qs_actable_st {
  apr_size_t size;
  apr_shm_t *m;
  char *m_file;
  apr_pool_t *pool;
  qs_acentry_t *entry;
  int child_init;
} qs_actable_t;

/**
 * server configuration
 */
typedef struct {
  apr_table_t *location_t;
  const char *error_page;
  qs_actable_t *act;
  int is_virtual;
  char *cookie_name;
  char *cookie_path;
  int max_age;
  unsigned char key[EVP_MAX_KEY_LENGTH];
  char *header_name;
} qos_srv_config;

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
 * destroys the act
 */
static apr_status_t qos_cleanup_shm(void *p) {
  qs_actable_t *act = p;
  qs_acentry_t *e = act->entry;
  act->child_init = 0;
  while(e) {
    apr_global_mutex_destroy(e->lock);
    e = e->next;
  }
  apr_shm_destroy(act->m);
  return APR_SUCCESS;
}

/**
 * init the shared memory act
 */
static apr_status_t qos_init_shm(server_rec *s, qs_actable_t *act, apr_table_t *table) {
  apr_status_t res;
  int i;
  int length = apr_table_elts(table)->nelts;
  if(length) {
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(table)->elts;
    qs_acentry_t *e;
    act->m_file = apr_psprintf(act->pool, "%s.mod_qos", ap_server_root_relative(act->pool, tmpnam(NULL)));
    act->size = length * APR_ALIGN_DEFAULT(sizeof(qs_acentry_t));
    res = apr_shm_create(&act->m, act->size + 512, act->m_file, act->pool);
    if (res != APR_SUCCESS) {
      char buf[MAX_STRING_LEN];
      apr_strerror(res, buf, sizeof(buf));
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                   QOS_LOG_PFX"could not create shared memory: %s", buf);
      return res;
    }
    act->entry = apr_shm_baseaddr_get(act->m);
    e = act->entry;
    for(i = 0; i < length; i++) {
      qs_rule_ctx_t *rule = (qs_rule_ctx_t *)entry[i].val;
      e->next = e + APR_ALIGN_DEFAULT(sizeof(qs_acentry_t *));
      e->id = i;
      e->url = rule->url;
      e->url_len = strlen(e->url);
      e->regex = rule->regex;
      e->limit = rule->limit;
      e->counter = 0;
      e->lock_file = apr_psprintf(act->pool, "%s.mod_qos", ap_server_root_relative(act->pool, tmpnam(NULL)));
      res = apr_global_mutex_create(&e->lock, e->lock_file, APR_LOCK_DEFAULT, act->pool);
      if (res != APR_SUCCESS) {
        char buf[MAX_STRING_LEN];
        apr_strerror(res, buf, sizeof(buf));
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                     QOS_LOG_PFX"could create mutex: %s", buf);
        return res;
      }
      if(i < length - 1) {
        e = e->next;
      } else {
        e->next = NULL;
      }
    }
    apr_pool_cleanup_register(act->pool, act, qos_cleanup_shm, apr_pool_cleanup_null);
  }
  return APR_SUCCESS;
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
 * handlers
 ***********************************************************************/

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
      apr_global_mutex_lock(e->lock);
      e->counter++;
      apr_global_mutex_unlock(e->lock);
      
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
                      QOS_LOG_PFX"access denied, rule: %s(%d), concurrent requests: %d",
                      e->url, e->limit, e->counter);
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
 * process response
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
  ap_remove_output_filter(f);
  return ap_pass_brigade (f->next, bb); 
}

/**
 * "free resources"
 */
static int qos_logger(request_rec * r) {
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  qs_acentry_t *e = rctx->entry;
  if(e) {
    char *h = apr_psprintf(r->pool, "%d", e->counter);
    apr_global_mutex_lock(e->lock);
    e->counter--;
    apr_global_mutex_unlock(e->lock);
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
    while(e) {
      /* attach to the mutex */
      apr_global_mutex_child_init(&e->lock, e->lock_file, sconf->act->pool);
      e = e->next;
    }
    while(s) {
      sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
      if(sconf->is_virtual) {
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
  char *rev = apr_pstrdup(ptemp, "$Revision: 2.3 $");
  char *er = strrchr(rev, ' ');
  server_rec *s = bs->next;
  int rules = 0;
  er[0] = '\0';
  rev++;

  if(qos_init_shm(bs, sconf->act, sconf->location_t) != APR_SUCCESS) {
    return !OK;
  }
  rules = apr_table_elts(sconf->location_t)->nelts;
  while(s) {
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    if(sconf->is_virtual) {
      if(qos_init_shm(s, sconf->act, sconf->location_t) != APR_SUCCESS) {
        return !OK;
      }
      rules = rules + apr_table_elts(sconf->location_t)->nelts;
    }
    s = s->next;
  }

  ap_log_error(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, bs,
               QOS_LOG_PFX"%s loaded (%d rules)", rev, rules);
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
static void *qos_srv_config_create(apr_pool_t * p, server_rec *s) {
  qos_srv_config *sconf=(qos_srv_config *)apr_pcalloc(p, sizeof(qos_srv_config));
  sconf->location_t = apr_table_make(p, 2);
  sconf->error_page = NULL;
  sconf->act = (qs_actable_t *)apr_pcalloc(p, sizeof(qs_actable_t));
  sconf->act->pool = p;
  sconf->act->m_file = NULL;
  sconf->act->child_init = 0;
  sconf->is_virtual = s->is_virtual;
  sconf->cookie_name = apr_pstrdup(p, QOS_COOKIE_NAME);
  sconf->cookie_path = apr_pstrdup(p, "/");
  sconf->max_age = atoi(QOS_MAX_AGE);
  sconf->header_name = NULL;
  {
    int len = EVP_MAX_KEY_LENGTH;
    unsigned char *rand = apr_pcalloc(p, len);
    RAND_bytes(rand, len);
    EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL, rand, len, 1, sconf->key, NULL);
  }
  return sconf;
}

/**
 * "merges" server configuration: virtual host overwrites global settings (if
 * any rule has been specified)
 */
static void *qos_srv_config_merge(apr_pool_t * p, void *basev, void *addv) {
  qos_srv_config *b = (qos_srv_config *)basev;
  qos_srv_config *o = (qos_srv_config *)addv;
  if(apr_table_elts(o->location_t)->nelts > 0) {
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
  EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL, seed, strlen(seed), 1, sconf->key, NULL);
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

static const command_rec qos_config_cmds[] = {
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
  AP_INIT_TAKE1("QS_ErrorPage", qos_error_page_cmd, NULL,
                RSRC_CONF,
                "QS_ErrorPage <url>, defines a custom error page."),
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
  NULL,
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void qos_register_hooks(apr_pool_t * p) {
  ap_hook_post_config(qos_post_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_child_init(qos_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_header_parser(qos_header_parser, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(qos_logger, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_insert_filter(qos_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
  ap_register_output_filter("qos-out-filter", qos_out_filter, NULL, AP_FTYPE_RESOURCE);
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
