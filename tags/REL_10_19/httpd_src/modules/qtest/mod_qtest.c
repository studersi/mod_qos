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
static const char revision[] = "$Id: mod_qtest.c,v 1.4 2013-08-29 19:43:51 pbuchbinder Exp $";

/************************************************************************
 * Includes
 ***********************************************************************/
/* openssl */
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

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

#include <mod_ssl.h>
#include <ssl_private.h>
#include <mod_core.h>

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
  if(strstr(r->parsed_uri.path, "/loginme/")) {
    apr_table_set(r->subprocess_env, "NEWSESSION", "1");
  }
  return DECLINED;
}
  
static int qtest_handler(request_rec * r) {
  if(strcmp(r->parsed_uri.path, "/killme/") == 0) {
    char *from = NULL;
    char *to = NULL;
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QTEST_LOG_PFX(001)"SEGFAULT %d", getpid());
    memcpy(to, from, 1);
  }
  if(strcmp(r->parsed_uri.path, "/loopme/") == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QTEST_LOG_PFX(001)"LOOP %d", getpid());
    while(1) {
      sleep(1);
    }
  }
  if(strcmp(r->parsed_uri.path, "/internalredirectme/") == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QTEST_LOG_PFX(001)"INTERNAL REDIRECT %d", getpid());
    r->method = apr_pstrdup(r->pool, "GET");
    r->method_number = M_GET;
    sleep(1);
    ap_internal_redirect(r->args, r);
    return OK;
  }
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
  return DECLINED;
}

/** finalize configuration */
static int qtest_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp,
                            server_rec *bs) {
  fprintf(stdout, "\033[1mmod_qtest - TEST MODULE, NOT FOR PRODUCTIVE USE\033[0m\n");
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
  ap_hook_handler(qtest_handler, pre, NULL, APR_HOOK_FIRST);
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

