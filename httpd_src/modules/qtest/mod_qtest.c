/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/* 
 * ######################################################################
 * THIS IS A TEST MODULE AND MUST NOT BE USED FOR PRODUCTIVE ENVIRONMENTS
 * ######################################################################
 */

/************************************************************************
 * Version
 ***********************************************************************/
static const char revision[] = "$Id$";

/************************************************************************
 * Includes
 ***********************************************************************/

#include <sys/types.h>
#include <unistd.h>

/* apache */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_connection.h"
#include "http_request.h"
#include "util_script.h"
#include "ap_mpm.h"
#include "mpm_common.h"
#include "ap_provider.h"

#define CORE_PRIVATE
#include <http_config.h>
#undef CORE_PRIVATE
#include <http_log.h>
#include <util_filter.h>
#include <ap_regex.h>

/* apr */
#include <apr_hooks.h>
#include <apr_strings.h>
#include <apr_date.h>
#include <apr_base64.h>


/************************************************************************
 * defines
 ***********************************************************************/
#define QTEST_LOG_PFX(id)  "mod_qtest("#id"): "

/************************************************************************
 * structures
 ***********************************************************************/

/************************************************************************
 * globals
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA qtest_module;

/************************************************************************
 * private
 ***********************************************************************/
typedef apr_array_header_t *(* hook_get_t)      (void);
typedef struct
{
    void (*pFunc) (void);       /* just to get the right size */
    const char *szName;
    const char *const *aszPredecessors;
    const char *const *aszSuccessors;
    int nOrder;
} hook_struct_t;

typedef struct
{
    const char *name;
    hook_get_t get;
} hook_lookup_t;

static hook_lookup_t request_hooks[] = {
    {"Pre-Connection", ap_hook_get_pre_connection},
    {"Create Connection", ap_hook_get_create_connection},
    {"Process Connection", ap_hook_get_process_connection},
    {"Create Request", ap_hook_get_create_request},
    //    {"Pre-Read Request", ap_hook_get_pre_read_request},
    {"Post-Read Request", ap_hook_get_post_read_request},
    {"Header Parse", ap_hook_get_header_parser},
    {"HTTP Scheme", ap_hook_get_http_scheme},
    {"Default Port", ap_hook_get_default_port},
    {"Quick Handler", ap_hook_get_quick_handler},
    {"Translate Name", ap_hook_get_translate_name},
    {"Map to Storage", ap_hook_get_map_to_storage},
    //    {"Check Access", ap_hook_get_access_checker_ex},
    {"Check Access (legacy)", ap_hook_get_access_checker},
    {"Verify User ID", ap_hook_get_check_user_id},
    //    {"Note Authentication Failure", ap_hook_get_note_auth_failure},
    {"Verify User Access", ap_hook_get_auth_checker},
    {"Check Type", ap_hook_get_type_checker},
    {"Fixups", ap_hook_get_fixups},
    {"Insert Filters", ap_hook_get_insert_filter},
    {"Content Handlers", ap_hook_get_handler},
    {"Transaction Logging", ap_hook_get_log_transaction},
    {"Insert Errors", ap_hook_get_insert_error_filter},
    //    {"Generate Log ID", ap_hook_get_generate_log_id},
    {NULL},
};

/************************************************************************
 * handlers
 ***********************************************************************/
static int qtest_fixup(request_rec * r) {

#ifdef QOS_TEST_MOD
  /**
   * DEVELOPMENT MODE ONLY
   * set NEWSESSION variable to simulate a session creation
   */
  if(strstr(r->parsed_uri.path, "/loginme/")) {
    apr_table_set(r->subprocess_env, "NEWSESSION", "1");
  }


  /**
   * DEVELOPMENT MODE ONLY
   * stores all request headers in mod_qos_ev to be logged within 
   * the access log file
   */
  if(r->args && strstr(r->args, "dumpheaders")) {
    const char *var = apr_table_get(r->subprocess_env, "mod_qos_ev");
    int i;
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(r->headers_in)->elts;
    for(i = 0; i < apr_table_elts(r->headers_in)->nelts; ++i) {
      var = apr_pstrcat(r->pool, e[i].key, "=", e[i].val, ";", var, NULL);
    }
    apr_table_set(r->subprocess_env, "mod_qos_ev", var);
  }
#endif

  /**
   * PUBLIC INTERFACE
   * delay for the number of microseconds as definied within the request
   * query parameter "delayus"
   */
  if(r->args) {
    const char *param = strstr(r->args, "delayus=");
    if(param) {
      char *value = apr_pstrdup(r->pool, &param[strlen("delayus=")]);
      char *end = value;
      apr_off_t delay = 0;
      while(end[0]) {
        end++;
        if(end[0] < '0' || end[0] > '9') {
          end[0] = '\0';
        }
      }
      delay = atol(value);
      apr_sleep(delay);
    } 
  }
  return DECLINED;
}

static int qtest_logger(request_rec *r) {
  const char *dumphdr = apr_table_get(r->headers_in, "X-dumpvar");
  if(dumphdr) {
    char *msg = "";
    int i;
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(r->subprocess_env)->elts;
    for (i = 0; i < apr_table_elts(r->subprocess_env)->nelts; ++i) {
      msg = apr_psprintf(r->pool, "%s=%s;%s",  e[i].key, e[i].val, msg);
    }
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QTEST_LOG_PFX(001)"VAR %s %s", r->unparsed_uri, msg);
  }
  return DECLINED;
}

static int qtest_handler(request_rec * r) {

  /**
   * DEVELOPMENT MODE ONLY
   * causes a segmentation fault (accessing a null pointer)
   */
  if(strcmp(r->parsed_uri.path, "/killme/") == 0) {
    char *from = NULL;
    char *to = NULL;
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QTEST_LOG_PFX(001)"SEGFAULT %d", getpid());
    memcpy(to, from, 1);
  }

  /**
   * DEVELOPMENT MODE ONLY
   * endless loop
   */
  if(strcmp(r->parsed_uri.path, "/loopme/") == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QTEST_LOG_PFX(001)"LOOP %d", getpid());
    while(1) {
      sleep(1);
    }
  }

  /**
   * DEVELOPMENT MODE ONLY
   * internal redirect to the sepcifed path (defined within the query)
   */
  if(strcmp(r->parsed_uri.path, "/internalredirectme/") == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QTEST_LOG_PFX(001)"INTERNAL REDIRECT %d", getpid());
    r->method = apr_pstrdup(r->pool, "GET");
    r->method_number = M_GET;
    sleep(1);
    ap_internal_redirect(r->args, r);
    return OK;
  }

  /**
   * DEVELOPMENT MODE ONLY
   * internal redirect to the error document
   */
  if(strcmp(r->parsed_uri.path, "/qstredirectme/") == 0) {
    r->method = apr_pstrdup(r->pool, "GET");
    r->method_number = M_GET;
    ap_internal_redirect("/error-docs/error_c.html", r);
    return OK;
  }

  /**
   * DEVELOPMENT MODE ONLY
   * internal redirect to doc which does not exist
   */
  if(strcmp(r->parsed_uri.path, "/qstredirectme404/") == 0) {
    r->method = apr_pstrdup(r->pool, "GET");
    r->method_number = M_GET;
    ap_internal_redirect("/error-docs/error_c_404.html", r);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  /**
   * DEVELOPMENT MODE ONLY
   */
  if(strcmp(r->parsed_uri.path, "/qstforbidden403/") == 0) {
    return HTTP_FORBIDDEN;
  }

  /**
   * DEVELOPMENT MODE ONLY
   * writes the variables to the response
   */
  if(strncmp(r->parsed_uri.path, "/dumpvar/", 9) == 0) {
    int i;
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(r->subprocess_env)->elts;
    ap_set_content_type(r, "text/plain");
    for (i = 0; i < apr_table_elts(r->subprocess_env)->nelts; ++i) {
      ap_rprintf(r, "var %s=%s\n",
                 ap_escape_html(r->pool, e[i].key),
                 ap_escape_html(r->pool, e[i].val));
    }
    return OK;
  }
  
  /**
   * DEVELOPMENT MODE ONLY
   * hook information
   */
  if(strcmp(r->parsed_uri.path, "/qsinfo/") == 0) {
    int i;
    ap_filter_t *f;
    ap_set_content_type(r, "text/plain");
    for(i = 0; request_hooks[i].name; i++) {
      apr_array_header_t *hooks = request_hooks[i].get();
      hook_struct_t *elts = (hook_struct_t *)hooks->elts;
      int j;
      ap_rprintf(r, "hook %s: ", request_hooks[i].name);
      for(j = 0; j < hooks->nelts; j++) {
        ap_rprintf(r,"%02d %s ", elts[j].nOrder, elts[j].szName);
      }
      ap_rputs("\n", r);
    }

    ap_rputs("std input-filter: ", r);
    f = r->input_filters;
     while(f) {
      ap_rprintf(r, "%s ", f->frec->name);
      f = f->next;
    }
    ap_rputs("\n", r);
    ap_rputs("std output-filter: ", r);
    f = r->output_filters;
    while(f) {
      ap_rprintf(r, "%s ", f->frec->name);
      f = f->next;
    }
    ap_rputs("\n", r);

    ap_rputs("protocol input-filter: ", r);
    f = r->proto_input_filters;
     while(f) {
      ap_rprintf(r, "%s ", f->frec->name);
      f = f->next;
    }
    ap_rputs("\n", r);
    ap_rputs("protocol output-filter: ", r);
    f = r->proto_output_filters;
    while(f) {
      ap_rprintf(r, "%s ", f->frec->name);
      f = f->next;
    }
    ap_rputs("\n", r);

    ap_rputs("connection input-filter: ", r);
    f = r->connection->input_filters;
     while(f) {
      ap_rprintf(r, "%s ", f->frec->name);
      f = f->next;
    }
    ap_rputs("\n", r);
    ap_rputs("connection output-filter: ", r);
    f = r->connection->output_filters;
    while(f) {
      ap_rprintf(r, "%s ", f->frec->name);
      f = f->next;
    }
    ap_rputs("\n", r);

    return OK;
  }

  /**
   * DEVELOPMENT MODE ONLY
   * returns 403
   */
  if(strncmp(r->parsed_uri.path, "/qsforbidden/", 13) == 0) {
    apr_table_set(r->subprocess_env, "qsforbidden", "true");
    return HTTP_FORBIDDEN;
  }
  return DECLINED;
}

/** finalize configuration */
static int qtest_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp,
                            server_rec *bs) {
  fprintf(stdout, "\033[1mmod_qtest - TEST MODULE, NOT FOR PRODUCTIVE USE\033[0m\n");
#ifndef QOS_TEST_MOD
  fprintf(stdout, "            %s\n", revision);
  fprintf(stdout, "            see https://sourceforge.net/projects/mod-qos/\n");
#endif
  fflush(stdout);
  return DECLINED;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/

/************************************************************************
 * apache register 
 ***********************************************************************/
static void qtest_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_qos.c", NULL };
  /* QOS_TEST_MOD must only be enabled when using the module within a
     development environment (includes segfault, endless loop, etc) */
#ifdef QOS_TEST_MOD
  ap_hook_handler(qtest_handler, pre, NULL, APR_HOOK_FIRST);
#endif
  ap_hook_fixups(qtest_fixup, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config(qtest_post_config, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(qtest_logger, pre, NULL, APR_HOOK_LAST);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA qtest_module ={ 
  STANDARD20_MODULE_STUFF,
  NULL,                                    /**< dir config creater */
  NULL,                                    /**< dir merger */
  NULL,                 /**< server config */
  NULL,                                    /**< server merger */
  NULL,                       /**< command table */
  qtest_register_hooks,                    /**< hook registery */
};

