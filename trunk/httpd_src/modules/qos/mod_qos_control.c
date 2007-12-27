/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * Quality of service module for Apache Web Server.
 *
 * This module is used to manage mod_qos rules.
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
static const char revision[] = "$Id: mod_qos_control.c,v 2.8 2007-12-27 13:51:38 pbuchbinder Exp $";

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
#include <apr_lib.h>

/* additional modules */
#include "mod_status.h"

/************************************************************************
 * defines
 ***********************************************************************/
#define QOSC_LOG_PFX(id)  "mod_qos_control("#id"): "
#define QOSC_SERVER_CONF  "server.conf"
#define QOSC_ACCESS_LOG   ".qs_access_log"
#define QOSC_RUNNING      ".qs_running"
#define QOSCR 13
#define QOSLF 10

/************************************************************************
 * structures
 ***********************************************************************/
typedef struct {
  char *path;
  char *qsfilter2;
} qosc_srv_config;

/************************************************************************
 * globals
 ***********************************************************************/

module AP_MODULE_DECLARE_DATA qos_control_module;

/************************************************************************
 * private functions
 ***********************************************************************/
int qosc_hex2c(const char *x) {
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

static int qosc_unescaping(char *x) {
  int i, j, ch;
  if (x[0] == '\0')
    return 0;
  for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
    ch = x[i];
    if (ch == '%' && isxdigit(x[i + 1]) && isxdigit(x[i + 2])) {
      ch = qosc_hex2c(&x[i + 1]);
      i += 2;
    }
    x[j] = ch;
  }
  x[j] = '\0';
  return j;
}

static int qosc_is_alnum(const char *string) {
  unsigned char *in = (unsigned char *)string;
  int i = 0;
  if(in == NULL) return 0;
  while(in[i]) {
    if(!apr_isalnum(in[i])) return 0;
    i++;
  }
  return 1;
}

static int qosc_fgetline(char *s, int n, FILE *f) {
  register int i = 0;
  while (1) {
    s[i] = (char) fgetc(f);
    if (s[i] == QOSCR) {
      s[i] = fgetc(f);
    }
    if ((s[i] == 0x4) || (s[i] == QOSLF) || (i == (n - 1))) {
      s[i] = '\0';
      return (feof(f) ? 1 : 0);
    }
    ++i;
  }
}

static void qosc_css(request_rec *r) {
   ap_rputs("  body {\n\
	background-color: white;\n\
	color: black;\n\
	font-family: arial, helvetica, verdana, sans-serif;\n\
  }\n\
  .btable{\n\
	  background-color: white;\n\
	  width: 98%;\n\
	  border: 1px solid;\n\
	  padding: 0px;\n\
	  margin: 6px;\n\
	  font-weight: normal;\n\
	  border-collapse: collapse;\n\
  }\n\
  .rowts {\n\
	  background-color: rgb(230,233,235);\n\
	  vertical-align: top;\n\
	  border: 1px solid;\n\
	  font-weight: bold;\n\
	  padding: 0px;\n\
	  margin: 0px;\n\
  }\n\
  .rowt {\n\
	  background-color: rgb(230,233,235);\n\
	  vertical-align: top;\n\
	  border: 1px solid;\n\
	  font-weight: normal;\n\
	  padding: 0px;\n\
	  margin: 0px;\n\
  }\n\
  .rows {\n\
	  background-color: rgb(240,243,245);\n\
	  vertical-align: top;\n\
	  border: 1px solid;\n\
	  font-weight: normal;\n\
	  padding: 0px;\n\
	  margin: 0px;\n\
  }\n\
  .row  {\n\
	  background-color: white;\n\
	  vertical-align: top;\n\
	  border: 1px solid;\n\
	  font-weight: normal;\n\
	  padding: 0px;\n\
	  margin: 0px;\n\
  }\n\
  .rowe {\n\
          background-color: rgb(210,216,220);\n\
	  vertical-align: top;\n\
          border: 1px solid;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  a:link    { color:black; text-decoration:none; }\n\
  a:visited { color:black; text-decoration:none; }\n\
  a:focus   { color:black; text-decoration:underline; }\n\
  a:hover   { color:black; text-decoration:none; }\n\
  a:active  { color:black; text-decoration:underline; }\n", r);
}

static char *qosc_get_path(request_rec *r) {
  char *path = apr_pstrdup(r->pool, r->parsed_uri.path);
  char *e;
  if(strstr(path, ".do") == NULL) {
    if(path[strlen(path)-1] == '/') {
      return ap_escape_html(r->pool, path);
    } else {
      return ap_escape_html(r->pool, apr_pstrcat(r->pool, path, "/", NULL));
    }
  }
  e = strrchr(path, '/');
  if(e == NULL) {
    return "/";
  }
  e++;
  e[0] = '\0';
  return ap_escape_html(r->pool, path);
}

static apr_table_t *qosc_get_query_table(request_rec *r) {
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

static void qosc_js_redirect(request_rec *r, const char *path) {
  ap_rputs("<script type=\"text/javascript\">\n", r);
  ap_rputs("<!-- \n", r);
  ap_rprintf(r, "location.replace(\"%s\");", path == NULL ? "" : ap_escape_html(r->pool, path));
  ap_rputs("//-->\n", r);
  ap_rputs("</script>\n", r);
  ap_rputs("You have disabled JavaScript.<br>\n", r);
  ap_rprintf(r, "Please follow <a href=\"%s\"><b>THIS</b></a> redirect link manually.\n",
             path == NULL ? "" : ap_escape_html(r->pool, path));
}

static void qosc_create_server(request_rec *r) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  apr_table_t *qt = qosc_get_query_table(r);
  const char *action = apr_table_get(qt, "action");
  const char *server = apr_table_get(qt, "server");
  if((server == NULL) || !qosc_is_alnum(server) ||
     (strcmp(server, "ct") == 0) ||
     (strcmp(server, "qsfilter2") == 0)) {
    ap_rputs("Unknown or invalid server name.", r);
  } else {
    if((action == NULL) || ((strcmp(action, "add") != 0) && (strcmp(action, "set") != 0))) {
      ap_rputs("Unknown action.", r);
    } else {
      if(strcmp(action, "set") == 0) {
        char *conf = (char *)apr_table_get(qt, "conf");
        FILE *f = NULL;
        if(conf) {
          conf = apr_pstrdup(r->pool, conf);
          qosc_unescaping(conf);
          f = fopen(conf, "r");
          if(f) {
            char *w = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
            if(mkdir(w, 0750) != 0) {
              ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                            QOSC_LOG_PFX(0)"failed to create directory '%s'", w); 
              ap_rprintf(r, "Failed to create directory '%s'", w);
              fclose(f);
              f=NULL;
            } else {
              char *sc = apr_pstrcat(r->pool, w, "/"QOSC_SERVER_CONF, NULL);
              FILE *c = fopen(sc, "w");
              if(c) {
                fprintf(c, "conf=%s\n", conf);
                fclose(c);
              }
            }
          }
        }
        if(f == NULL) {
          // failed
          ap_rprintf(r, "Could not open server configuration '%s'",
                     conf == NULL ? "-" : ap_escape_html(r->pool, conf));
          action = "add";
        } else {
          qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), server,
                                          ".do?action=load", NULL));
          fclose(f);
        }
      }
      if(strcmp(action, "add") == 0) {
        char *w = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
        DIR *dir = opendir(w);
        if(!dir){ 
          ap_rprintf(r, "<form action=\"%sct.do\" method=\"get\">\n",
                     qosc_get_path(r));
          ap_rprintf(r, "Specify the server configuration file (httpd.conf) for '%s':<br>\n"
                     " <input name=\"conf\" value=\"&lt;path&gt;\" type=\"text\" size=\"50\">\n"
                     " <input name=\"server\" value=\"%s\"    type=\"hidden\">\n"
                     " <input name=\"action\" value=\"set\" type=\"submit\">\n"
                     " </form>\n", ap_escape_html(r->pool, server),
                     ap_escape_html(r->pool, server));
        } else {
          closedir(dir);
          ap_rprintf(r, "Server '%s' already exists.",
                     ap_escape_html(r->pool, server));
        }
      }
    }
  }
  
}

static const char *qosc_get_conf_value(const char *line, const char *directive) {
  char *v = ap_strcasestr(line, directive);
  char *c = strchr(line, '#');
  if(v) {
    if(v > line) {
      char *t = v;
      t--;
      if((t[0] != ' ') && (t[0] != '\t') && (t[0] != '<')) {
        return NULL;
      }
    }
    if(c && (c<v)) return NULL;
    v = &v[strlen(directive)];
    while((v[0] == ' ') || (v[0] == '\t')) v++;
  }
  return v;
}

static void qosc_load_httpdconf(request_rec *r, const char *file, const char *root, STACK *st, int *errors) {
  FILE *f = fopen(file, "r");
  char line[HUGE_STRING_LEN];
  if(f) {
    while(!qosc_fgetline(line, sizeof(line), f)) {
      const char *inc = qosc_get_conf_value(line, "Include ");
      const char *host = qosc_get_conf_value(line, "VirtualHost ");
      const char *loc = qosc_get_conf_value(line, "Location ");
      if(inc) {
        /* server MUST use relative includes only!
         *  root=/etc/apache/conf
         *  inc=conf/sub.conf
         */
        char *search = apr_pstrdup(r->pool, inc);
        char *fl = strchr(search, '/');
        char *base = apr_pstrdup(r->pool, root);
        char *e;
        if(fl) {
          fl[0] = '\0';
          fl++;
        }
        e = strstr(base, search);
        if(e && fl) {
          char *incfile;
          e[strlen(search)] = '\0';
          incfile = apr_pstrcat(r->pool, base, "/", fl, NULL);
          qosc_load_httpdconf(r, incfile, root, st, errors);
        } else {
          errors++;
          ap_rprintf(r, "Failed to resolve '%s'.<br>\n", ap_escape_html(r->pool, line));
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        QOSC_LOG_PFX(0)"failed to find included httpd configuration file '%s'",
                        line);
        }
      }
      if(loc) {
        char *end = (char *)loc;
        while(end[0] && (end[0] != ' ') && (end[0] != '>') && (end[0] != '\t')) end++;
        end[0] = '\0';
        sk_push(st, apr_pstrcat(r->pool, "location=", loc, NULL));
      }
      if(host) {
        char *end = (char *)host;
        while(end[0] && (end[0] != ' ') && (end[0] != '>') && (end[0] != '\t')) end++;
        end[0] = '\0';
        sk_push(st, apr_pstrcat(r->pool, "host=", host, NULL));
      }
    }
    fclose(f);
  } else {
    errors++;
    ap_rprintf(r, "Failed to open '%s'.<br>\n", ap_escape_html(r->pool, file));
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"failed to open httpd configuration file '%s'", file); 
  }
}

static void qosc_server_load(request_rec *r, const char *server) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  char *server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
  char *server_conf = apr_pstrcat(r->pool, server_dir, "/"QOSC_SERVER_CONF, NULL);
  STACK *st = sk_new(NULL);
  FILE *f = fopen(server_conf, "r");
  char line[HUGE_STRING_LEN];
  char *httpdconf;
  char *root;
  char *p;
  int errors = 0;
  line[0] = '\0';
  if(!f) {
    ap_rputs("Could not open server settings.", r);
    return;
  }
  qosc_fgetline(line, sizeof(line), f);
  fclose(f);
  httpdconf = apr_pstrdup(r->pool, line);
  if(strncmp(httpdconf, "conf=", strlen("conf=")) != 0) {
    ap_rputs("Invalid server settings.", r);
    return;
  }
  httpdconf = httpdconf + strlen("conf=");
  root = apr_pstrdup(r->pool, httpdconf);
  p = strrchr(root, '/');
  if(p) p[0] = '\0';
  sk_push(st, apr_pstrdup(r->pool, line));

  qosc_load_httpdconf(r, httpdconf, root, st, &errors);
  f = fopen(server_conf, "w");
  if(f) {
    int i;
    for(i = 0; i < sk_num(st); i++) {
      char *l = sk_value(st, i);
      fprintf(f, "%s\n", l);
    }
    fclose(f);
  } else {
    errors++;
    ap_rprintf(r, "Failed to write '%s'.<br>\n", ap_escape_html(r->pool, server_conf));
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"failed to write to '%s'", server_conf);
  }
  sk_free(st);
  if(errors == 0) {
    qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), server, ".do", NULL));
  }
}

static void qosc_qsfilter2_upload(request_rec *r) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  apr_table_t *qt = qosc_get_query_table(r);
  const char *server = apr_table_get(qt, "server");
  const char *action = apr_table_get(qt, "action");
  char *server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
  char *access_log = apr_pstrcat(r->pool, server_dir, "/"QOSC_ACCESS_LOG, NULL);
  if((r->method_number != M_POST) || !server || !action) {
    ap_rputs("Invalid request.", r);
    return;
  }
  if(strcmp(action, "upload") == 0) {
    /* receives an access log file */
  } else {
    ap_rputs("Unknown action.", r);
    return;
  }
}

static void qosc_server_qsfilter2(request_rec *r, const char *server) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  char *server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
  char *server_conf = apr_pstrcat(r->pool, server_dir, "/"QOSC_SERVER_CONF, NULL);
  char *access_log = apr_pstrcat(r->pool, server_dir, "/"QOSC_ACCESS_LOG, NULL);
  char *running_file = apr_pstrcat(r->pool, server_dir, "/"QOSC_RUNNING, NULL);
  int inprogress = 0;

  struct stat attrib;
  if(stat(running_file, &attrib) == 0) {
    inprogress = 1;
  }
  ap_rputs("<table class=\"btable\"><tbody>\n",r);

  ap_rputs("<tr class=\"row\"><td>\n",r);
  ap_rputs("Use qsfilter2 to generate request line white list rules.<br><br>\n", r);
  ap_rputs("</td></tr>", r);


  /* file upload */
  if(!inprogress) {
    ap_rputs("<tr class=\"rows\"><td>\n",r);
    ap_rputs("Upload access log data:", r);
    ap_rprintf(r, "<form action=\"%sqsfilter2.do?server=%s&action=upload\""
               " method=\"post\" enctype=\"multipart/form-data\">\n",
               qosc_get_path(r), ap_escape_html(r->pool, server));
    ap_rprintf(r, " <input name=\"access_log\" value=\"\" type=\"file\">\n"
               " <input name=\"action\" value=\"upload\" type=\"submit\">\n"
               " </form>\n", ap_escape_html(r->pool, server));
    ap_rputs("</td></tr>", r);
  }

  /* start analysis */
  ap_rputs("<tr class=\"rows\"><td>\n",r);
  if(!inprogress) {
    ap_rprintf(r, "<form action=\"%sqsfilter2.do\">\n",
               qosc_get_path(r));
    ap_rputs("Generate rules:", r);
    ap_rprintf(r, " <input name=\"server\" value=\"%s\"    type=\"hidden\">\n"
               " <input name=\"action\" value=\"start\" type=\"submit\">\n"
               " </form>\n", ap_escape_html(r->pool, server));
  } else {
    ap_rputs("<br>Rule generation process is running.<br>Please wait.<br><br>\n", r);
  }
  ap_rputs("</td></tr>", r);

  ap_rputs("</tbody></table>\n", r);
}

static void qosc_server(request_rec *r) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  const char *server = strrchr(apr_pstrdup(r->pool, r->parsed_uri.path), '/');
  char *server_dir = NULL;
  DIR *dir;
  apr_table_t *qt = qosc_get_query_table(r);
  const char *location = apr_table_get(qt, "loc");
  const char *action = apr_table_get(qt, "action");


  if(server) {
    char *serverend = strstr(server, ".do");
    server++;
    if(serverend == NULL) {
      ap_rputs("Could not determine server name.<br>", r);
      ap_rputs("Please choose or create a server.", r);
      return;
    }
    serverend[0] = '\0';
  } else {
    ap_rputs("Could not determine server name.<br>", r);
    ap_rputs("Please choose or create a server.", r);
    return;
  }
  server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
  dir = opendir(server_dir);
  if(dir == NULL) {
    ap_rputs("Could not open server directory.", r);
    return;
  }
  if(action && (strcmp(action, "load") == 0)) {
    qosc_server_load(r, server);
  }
  if(action && (strcmp(action, "qsfilter2") == 0)) {
    qosc_server_qsfilter2(r, server);
  }
}

static void qosc_body(request_rec *r) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  if(strstr(r->parsed_uri.path, "/ct.do") != NULL) {
    qosc_create_server(r);
    return;
  }
  if(strstr(r->parsed_uri.path, "/qsfilter2.do") != NULL) {
    qosc_qsfilter2_upload(r);
    return;
  }
  if(!sconf->qsfilter2) {
    ap_rputs("No qsfilter2 executable defined.", r);
  }
  qosc_server(r);
}

static void qosc_server_list(request_rec *r) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  struct dirent *de;
  DIR *dir = opendir(sconf->path);
  if(dir) {
    while((de = readdir(dir)) != 0) {
      if(de->d_name[0] != '.') {
        char *h = apr_psprintf(r->pool, "/%s.do", de->d_name);
        if(strstr(r->parsed_uri.path, h) != NULL) {
          ap_rprintf(r, "<tr class=\"rowts\"><td>"
                     "<a href=\"%s%s.do\">%s</a></td></tr>\n",
                     qosc_get_path(r), ap_escape_html(r->pool, de->d_name),
                     ap_escape_html(r->pool, de->d_name));
          ap_rprintf(r, "<tr class=\"row\"><td>"
                     "&nbsp;<a href=\"%s%s.do?action=qsfilter2\">qsfilter2</a></td></tr>\n",
                     qosc_get_path(r), ap_escape_html(r->pool, de->d_name));
          ap_rprintf(r, "<tr class=\"row\"><td>"
                     "&nbsp;<a href=\"%s%s.do?action=load\">reload configuration</a></td></tr>\n",
                     qosc_get_path(r), ap_escape_html(r->pool, de->d_name));
        } else {
          ap_rprintf(r, "<tr class=\"rowt\"><td>"
                     "<a href=\"%s%s.do\">%s</a></td></tr>\n",
                     qosc_get_path(r), ap_escape_html(r->pool, de->d_name),
                     ap_escape_html(r->pool, de->d_name));
        }
      }
    }
    closedir(dir);
  } else {
    if(mkdir(sconf->path, 0750) != 0) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOSC_LOG_PFX(0)"failed to create directory '%s'", sconf->path); 
    }
  }
}

/************************************************************************
 * "public"
 ***********************************************************************/

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * to amuse ...
 */
static int qosc_favicon(request_rec *r) {
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
static int qosc_handler(request_rec * r) {
  if (strcmp(r->handler, "qos-control") != 0) {
    return DECLINED;
  } 
  if(strstr(r->parsed_uri.path, "favicon.ico") != NULL) {
    return qosc_favicon(r);
  }
  ap_set_content_type(r, "text/html");
  //  apr_table_set(r->headers_out,"Cache-Control","no-cache");
  if(!r->header_only) {
    ap_rputs("<html><head><title>mod_qos control</title>\n", r);
    ap_rprintf(r,"<link rel=\"shortcut icon\" href=\"%s/favicon.ico\"/>\n",
               ap_escape_html(r->pool, r->parsed_uri.path));
    ap_rputs("<meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n", r);
    ap_rputs("<meta name=\"author\" content=\"Pascal Buchbinder\">\n", r);
    ap_rputs("<meta http-equiv=\"Pragma\" content=\"no-cache\">\n", r);
    ap_rputs("<style TYPE=\"text/css\">\n", r);
    ap_rputs("<!--", r);
    qosc_css(r);
    ap_rputs("-->\n", r);
    ap_rputs("</style>\n", r);
    ap_rputs("<script language=\"JavaScript\" type=\"text/javascript\">\n\
<!--\n\
function checkserver ( form ) {\n\
  if(form.server.value == \"ct\") {\n\
    alert(\"Sorry, this is a reserved word. Please choose another server name.\" );\n\
    return false;\n\
  }\n\
  if(form.server.value == \"qsfilter2\") {\n\
    alert(\"Sorry, this is a reserved word. Please choose another server name.\" );\n\
    return false;\n\
  }\n\
  if(form.server.value == \"\") {\n\
    alert(\"Please define a server name.\" );\n\
    return false;\n\
  }\n\
  var chkZ = 1;\n\
  for(i = 0; i < form.server.value.length; ++i)\n\
    if((form.server.value.charAt(i) < \"0\") ||\n\
       ((form.server.value.charAt(i) > \"9\") && (form.server.value.charAt(i) < \"a\")) ||\n\
       (form.server.value.charAt(i) > \"z\")) {\n\
      chkZ = -1;\n\
  }\n\
  if (chkZ == -1) {\n\
    alert(\"Allowed character set for server name: [0-9a-z].\" );\n\
    return false;\n\
  }\n\
  return true;\n\
}\n\
//-->\n\
</script>\n", r);
    ap_rputs("</head><body>", r);

    ap_rputs("<h2>mod_qos control</h2>\n\
<table class=\"btable\">\n\
  <tbody>\n\
    <tr class=\"row\">\n\
      <td style=\"width: 230px;\" >\n\
      <table class=\"btable\">\n\
        <tbody>\n", r);
    qosc_server_list(r);
    ap_rputs("          <tr class=\"rowe\">\n\
            <td>\n", r);
    ap_rprintf(r, "<form action=\"%sct.do\" method=\"get\" onsubmit=\"return checkserver(this);\">\n",
               qosc_get_path(r));
    ap_rputs("Add a new server:\n\
              <input name=\"server\" value=\"\"    type=\"text\">\n\
              <input name=\"action\" value=\"add\" type=\"submit\">\n\
            </form>\n\
            </td>\n\
          </tr>\n\
        </tbody>\n\
      </table>\n\
      </td>\n\
      <td >\n", r);
    /* TEXT */
    qosc_body(r);
    ap_rputs("      </td>\n\
    </tr>\n\
  </tbody>\n\
</table>\n", r);
    ap_rputs("</body></html>", r);
  }
  return OK;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/

static void *qosc_dir_config_create(apr_pool_t *p, char *d) {
  return NULL;
}

static void *qosc_dir_config_merge(apr_pool_t *p, void *basev, void *addv) {
  return addv;
}

static void *qosc_srv_config_create(apr_pool_t *p, server_rec *s) {
  qosc_srv_config *sconf = apr_pcalloc(p, sizeof(qosc_srv_config));
  sconf->path = apr_pstrdup(p, "/var/tmp/qos_control");
  sconf->qsfilter2 = NULL;
  return sconf;
}

static void *qosc_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  return basev;
}

const char *qosc_wd_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                  &qos_control_module);
  DIR *dir;
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if((strlen(path) < 0) || (path[0] != '/')) {
    return apr_psprintf(cmd->pool, "%s: invalid path", 
                        cmd->directive->directive);
  }
  sconf->path = apr_pstrdup(cmd->pool, path);
  dir = opendir(sconf->path);
  if(dir) {
    closedir(dir);
  } else {
    if(mkdir(sconf->path, 0750) != 0) {
      return apr_psprintf(cmd->pool, "%s: could not create directory '%s'",
                          cmd->directive->directive, path);
    }
  }
  return NULL;
}

const char *qosc_filter2_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  qosc_srv_config *sconf = (qosc_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                  &qos_control_module);
  struct stat attrib;
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if((strlen(path) < 0) || (path[0] != '/')) {
    return apr_psprintf(cmd->pool, "%s: invalid path",
                        cmd->directive->directive);
  }
  sconf->qsfilter2 = apr_pstrdup(cmd->pool, path);
  if(stat(sconf->qsfilter2, &attrib) != 0) {
    return apr_psprintf(cmd->pool, "%s: invalid path, file not available",
                        cmd->directive->directive);
  }
  if(!(attrib.st_mode & S_IXUSR)) {
    return apr_psprintf(cmd->pool, "%s: not executable",
                        cmd->directive->directive);
  }
  return NULL;
}

static const command_rec qosc_config_cmds[] = {
  AP_INIT_TAKE1("QSC_WorkingDirectory", qosc_wd_cmd, NULL,
                RSRC_CONF,
                "QSC_WorkingDirectory <path>, defines the working diretory where qos control"
                " stores is data. Default is /var/tmp/qos_control."
                " Directive is allowed in global server context only."),
  AP_INIT_TAKE1("QSC_Filter2Binary", qosc_filter2_cmd, NULL,
                RSRC_CONF,
                "QSC_Filter2Binary <path>, defines the path of the qsfilter2"
                " binary. Specification is mandatory."
                " Directive is allowed in global server context only."),
  NULL,
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void qosc_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_setenvif.c", NULL };
  ap_hook_handler(qosc_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA qos_control_module ={ 
  STANDARD20_MODULE_STUFF,
  qosc_dir_config_create,                    /**< dir config creater */
  qosc_dir_config_merge,                     /**< dir merger */
  qosc_srv_config_create,                    /**< server config */
  qosc_srv_config_merge,                     /**< server merger */
  qosc_config_cmds,                          /**< command table */
  qosc_register_hooks,                       /**< hook registery */
};
