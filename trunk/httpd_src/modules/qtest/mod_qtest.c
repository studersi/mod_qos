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

/* apache */
#include <httpd.h>
#include <http_main.h>
#include <http_request.h>
#include <http_connection.h>
#include <http_protocol.h>
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
   * writes the variables to the response
   */
  if(strcmp(r->parsed_uri.path, "/dumpvar/") == 0) {
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

