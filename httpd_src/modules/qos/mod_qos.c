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
 * This release features the following features:
 * - Limits the number of concurrent requests for a location. The
 *   implementation uses the scoreboard to determine the number
 *   of concurrent requests per location.
 * - Customizable error page for denied requests.
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

static const char rcsid[] = "$Header: /home/cvs/m/mo/mod-qos/src/httpd_src/modules/qos/mod_qos.c,v 1.3 2007-05-21 20:10:38 pbuchbinder Exp $";

/************************************************************************
 * Includes
 ***********************************************************************/
/* apache */
#define CORE_PRIVATE
#include <httpd.h>
#include <http_protocol.h>
#include <http_main.h>
#include <time.h>
#include <ap_mpm.h>
#include <scoreboard.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <util_filter.h>

/* apr */
#include <apr_strings.h>

/************************************************************************
 * defines
 ***********************************************************************/
#define QOS_LOG_PFX "mod_qos: "

/************************************************************************
 * structures
 ***********************************************************************/

/** Server configuration */
typedef struct {
  apr_table_t *location_t;
  int default_loc_limit;
  const char *error_page;
} qos_srv_config;

/************************************************************************
 * globals
 ***********************************************************************/

module AP_MODULE_DECLARE_DATA qos_module;
int server_limit, thread_limit;

/************************************************************************
 * private functions
 ***********************************************************************/

/**
 * Returns custom error page
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

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * Header parser implements restrictions on a per location (url) basis.
 */
static int qos_header_parser(request_rec * r) {
  int ret = DECLINED;
  if (ap_extended_status) {
    qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
    int i, j;
    int is_threaded;
    worker_score *ws_record;

    /* get the request limitation for this location */
    int limit = sconf->default_loc_limit;
    const char *limit_location = apr_pstrdup(r->pool, "/");
    int limit_location_len = strlen(limit_location);
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->location_t)->elts;
    for(i = 0; i < apr_table_elts(sconf->location_t)->nelts; i++) {
      if(strncmp(entry[i].key, r->parsed_uri.path, strlen(entry[i].key)) == 0) {
        limit = atoi(entry[i].val);
        limit_location = entry[i].key;
        limit_location_len = strlen(limit_location);
        break;
      }
    }

    /* iterate through the scoreboard and count the requests to this location */
    if(limit) {
      int current = 0;
      for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
          ws_record = ap_get_scoreboard_worker(i, j);

          if (ws_record->access_count == 0 &&
              (ws_record->status == SERVER_READY ||
               ws_record->status == SERVER_DEAD)) {
            continue;
          }
          if(((ws_record->status == SERVER_BUSY_READ) ||
              (ws_record->status == SERVER_BUSY_LOG) ||
              (ws_record->status == SERVER_BUSY_WRITE)) &&
             (ws_record->request != NULL)) {
            char *p = strchr(ws_record->request, ' ');
            if(p) {
              p++;
              if(strncmp(limit_location, p, limit_location_len) == 0) {
                current++;
              }
            }
          }
        }
      }
      /* enforce the limitation */
      if(current > limit) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOS_LOG_PFX"access denied, rule: %s(%d), concurrent requests: %d",
                      limit_location, limit, current);
        if(sconf->error_page) {
          qos_error_response(r, sconf->error_page);
          return DONE;
        } 
        return HTTP_INTERNAL_SERVER_ERROR;
      }
    }
  }
  return ret;
}

/**
 * Intit the server configuration
 */
static int qos_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *bs) {
  char *rev = apr_pstrdup(ptemp, "$Revision: 1.3 $");
  char *e = strrchr(rev, ' ');
  e[0] = '\0';
  rev++;
  ap_log_error(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, bs,
               QOS_LOG_PFX"%s loaded %s", rev,
               ap_extended_status == 0 ? "but not active" : "and active");

  ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &server_limit);
  ap_mpm_query(AP_MPMQ_MAX_THREADS, &thread_limit);
  if(thread_limit == 0) thread_limit = 1; // mpm prefork

  return DECLINED;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
static void *qos_srv_config_create(apr_pool_t * p, server_rec *s) {
  qos_srv_config *sconf=(qos_srv_config *)apr_pcalloc(p, sizeof(qos_srv_config));
  sconf->location_t = apr_table_make(p, 2);
  sconf->default_loc_limit = 0; /** no limitation */
  sconf->error_page = NULL;
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
 * Command to define the concurrent request limitation for a location
 */
const char *qos_loc_con_cmd(cmd_parms * cmd, void *dcfg, const char *loc, const char *limit) {
  qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  apr_table_add(sconf->location_t, loc, limit);
  ap_extended_status = 1;
  return NULL;
}

/**
 * Sets the default limitation of cuncurrent requests
 */
const char *qos_loc_con_def_cmd(cmd_parms * cmd, void *dcfg, const char *limit) {
  qos_srv_config* sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->default_loc_limit = atoi(limit);
  ap_extended_status = 1;
  return NULL;
}

/**
 * Defines custom error page
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
  /* register hooks */
  ap_hook_post_config(qos_post_config, NULL, NULL, APR_HOOK_LAST);
  ap_hook_header_parser(qos_header_parser, NULL, NULL, APR_HOOK_LAST);
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
