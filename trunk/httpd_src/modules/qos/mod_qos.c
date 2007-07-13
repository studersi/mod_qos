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
 * - QS_LocRequestLimit/QS_LocRequestLimitDefault:
 *   Limits the number of concurrent requests for a location.
 * - QS_ErrorPage:
 *   Customizable error page for denied requests.
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

static const char revision[] = "$Id: mod_qos.c,v 1.5 2007-07-13 19:12:15 pbuchbinder Exp $";

/************************************************************************
 * Includes
 ***********************************************************************/
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

/************************************************************************
 * structures
 ***********************************************************************/

/** access table entry */
typedef struct qs_acentry_st {
  int id;
  apr_global_mutex_t *lock;
  int counter;
  int limit;
  struct qs_acentry_st *next;
  int url_len;
  char *lock_file;
  char *url;
} qs_acentry_t;

/** access table */
typedef struct qs_actable_st {
  apr_size_t size;
  apr_shm_t *m;
  char *m_file;
  apr_pool_t *pool;
  qs_acentry_t *entry;
  int child_init;
} qs_actable_t;

/** server configuration */
typedef struct {
  apr_table_t *location_t;
  const char *error_page;
  qs_actable_t *act;
  int is_virtual;
} qos_srv_config;

/** request configuration */
typedef struct {
  qs_acentry_t *entry;
} qs_req_ctx;

/** rule set */
typedef struct {
  char *url;
  int limit;
  //ap_regex_t *regex;
} qs_rule_ctx_t;


/************************************************************************
 * globals
 ***********************************************************************/

module AP_MODULE_DECLARE_DATA qos_module;

/************************************************************************
 * private functions
 ***********************************************************************/

static qs_req_ctx *qos_rctx_config_get(request_rec *r) {
  qs_req_ctx *rctx = ap_get_module_config(r->request_config, &qos_module);
  if(rctx == NULL) {
    rctx = apr_pcalloc(r->pool, sizeof(qs_req_ctx));
    rctx->entry = NULL;
    ap_set_module_config(r->request_config, &qos_module, rctx);
  }
  return rctx;
}

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
 * returns the best matching location entry
 */
static qs_acentry_t *qos_getlocation(request_rec * r, qos_srv_config* sconf) {
  qs_acentry_t *ret = NULL;
  qs_actable_t *act = sconf->act;
  qs_acentry_t *e = act->entry;
  int match = 0;
  while(e) {
    if(strncmp(e->url, r->parsed_uri.path, e->url_len) == 0) {
      /* best match */
      if(e->url_len > match) {
        match = e->url_len;
        ret = e;
      }
    }
    e = e->next;
  }
  return ret;
}

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * header parser implements restrictions on a per location (url) basis.
 */
static int qos_header_parser(request_rec * r) {
  qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);

  /*
   * QS_LocRequestLimit/QS_LocRequestLimitDefault enforcement
   */
  qs_acentry_t *e = qos_getlocation(r, sconf);
  if(e) {
    qs_req_ctx *rctx = qos_rctx_config_get(r);
    rctx->entry = e;
    apr_global_mutex_lock(e->lock);
    e->counter++;
    apr_global_mutex_unlock(e->lock);

    /* enforce the limitation */
    if(e->counter > e->limit) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOS_LOG_PFX"access denied, rule: %s(%d), concurrent requests: %d",
                    e->url, e->limit, e->counter);
      if(sconf->error_page) {
        qos_error_response(r, sconf->error_page);
        return DONE;
      }
      return HTTP_INTERNAL_SERVER_ERROR;
    }
  }
  return DECLINED;
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
  }
  return DECLINED;
}

/**
 * inits each child
 */
static void qos_child_init(apr_pool_t *p, server_rec *bs) {
  server_rec *s = bs->next;
  qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  qs_acentry_t *e = sconf->act->entry;
  if(!sconf->act->child_init) {
    sconf->act->child_init = 1;
    while(e) {
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
  qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  char *rev = apr_pstrdup(ptemp, "$Revision: 1.5 $");
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
  return sconf;
}

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
  qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *id = apr_psprintf(cmd->pool, "%d", apr_table_elts(sconf->location_t)->nelts);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  rule->url = apr_pstrdup(cmd->pool, loc);
  rule->limit = atoi(limit);
  //rule->regex = NULL;
  apr_table_setn(sconf->location_t, id, (char *)rule);
  return NULL;
}

/**
 * sets the default limitation of cuncurrent requests
 */
const char *qos_loc_con_def_cmd(cmd_parms * cmd, void *dcfg, const char *limit) {
  qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  return qos_loc_con_cmd(cmd, dcfg, "/", limit);
}

/**
 * defines custom error page
 */
const char *qos_error_page_cmd(cmd_parms * cmd, void *dcfg, const char *path) {
  qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->error_page = apr_pstrdup(cmd->pool, path);
  if(sconf->error_page[0] != '/') {
    return apr_psprintf(cmd->pool, "%s: requires absolute path (%s)", 
                        cmd->directive->directive, sconf->error_page);
  }
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
                " QS_LocRequestLimit directive."),
  AP_INIT_TAKE1("QS_ErrorPage", qos_error_page_cmd, NULL,
                RSRC_CONF,
                "QS_ErrorPage <url>, defines a custom error page."),
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
