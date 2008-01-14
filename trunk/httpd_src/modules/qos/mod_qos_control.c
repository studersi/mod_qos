/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * Configuration tool for mod_qos, a quality of service
 * module for Apache Web Server.
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
static const char revision[] = "$Id: mod_qos_control.c,v 2.41 2008-01-14 21:16:46 pbuchbinder Exp $";

/************************************************************************
 * Includes
 ***********************************************************************/
#include <sys/types.h>
#include <sys/stat.h>

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

/************************************************************************
 * defines
 ***********************************************************************/
#define QOSC_LOG_PFX(id)  "mod_qos_control("#id"): "
#define QOSC_SERVER_CONF  "server.conf"
#define QOSC_SERVER_OPTIONS "qsfilter2.options"
#define QOSC_ACCESS_LOG   ".qs_access_log"
#define QOSC_RUNNING      ".qs_running"
#define QOSC_STATUS       ".qs_status"
#define QOSCR 13
#define QOSLF 10
#define QOSC_HUGE_STRING_LEN 32768
#define QOSC_REQ          "(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|BCOPY|BDELETE|BMOVE|BPROPFIND|BPROPPATCH|NOTIFY|POLL|SUBSCRIBE|UNSUBSCRIBE|X-MS-ENUMATTS|RPC_IN_DATA|RPC_OUT_DATA) /[\x20-\x21\x23-\xFF]* HTTP/"

/************************************************************************
 * structures
 ***********************************************************************/
typedef struct {
  apr_pool_t *pool;
  char *path;
  char *qsfilter2;
  char *viewer;
} qosc_srv_config_t;

typedef struct {
  char *name;
  char *uri;
  FILE *fd;
} qosc_location_t;

typedef struct {
  const char *server;
  char *server_dir;
  char *server_conf;
  char *server_options;
  char *access_log;
  char *running_file;
  char *status_file;
  qosc_srv_config_t *sconf;
  apr_table_t *qt;
} qosc_settings_t;

/************************************************************************
 * globals
 ***********************************************************************/

module AP_MODULE_DECLARE_DATA qos_control_module;

/************************************************************************
 * private functions
 ***********************************************************************/
static char *qosc_revision(apr_pool_t *p) {
  char *ver = apr_pstrdup(p, strchr(revision, ' '));
  char *h;
  ver++;
  ver =strchr(ver, ' ');
  ver++;
  h = strchr(ver, ' ');
  h[0] = '\0';
  return ver;
}

static void qosc_log(apr_pool_t *pool, char *fmt, ...) {
  char *msg;
  va_list va;
  char *time_string;
  time_t t = time(NULL);
  time_string = ctime(&t);
  time_string[strlen(time_string) - 1] = '\0';
  va_start(va, fmt);
  msg = apr_pvsprintf(pool, fmt, va);
  fprintf(stderr, "[%s] [notice] mod_qos_control: %s\n", time_string, msg);
  fflush(stderr);
}

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

static int qos_ishex(char x) {
  if((x >= '0') && (x <= '9')) return 1;
  if((x >= 'a') && (x <= 'f')) return 1;
  if((x >= 'A') && (x <= 'F')) return 1;
  return 0;
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
    if (ch == '\\' && (x[i + 1] == 'x') && qos_ishex(x[i + 2]) && qos_ishex(x[i + 3])) {
      ch = qosc_hex2c(&x[i + 2]);
      i += 3;
    }
    x[j] = ch;
  }
  x[j] = '\0';
  return j;
}

static char *qosc_pcre_escape(apr_pool_t *pool, const char *string) {
  unsigned char *in = (unsigned char *)string;
  char *ret = apr_pcalloc(pool, strlen(string) * 4);
  int i = 0;
  int reti = 0;
  while(in[i]) {
    if(strchr("{}[]()^$.|*+?\"'", in[i]) != NULL) {
      ret[reti] = '\\';
      reti++;
      ret[reti] = in[i];
      reti++;
    } else {
      ret[reti] = in[i];
      reti++;
    }
    i++;
  }
  ret[reti] = '\0';
  return ret;
}

static int qosc_is_alnum_uc(const char *string) {
  unsigned char *in = (unsigned char *)string;
  int i = 0;
  if(in == NULL) return 0;
  while(in[i]) {
    if(!apr_isalnum(in[i]) && (in[i] != '_')) return 0;
    i++;
  }
  return 1;
}

static const char *qosc_get_server(apr_table_t *qt) {
  const char *server = apr_table_get(qt, "server");
  if(!server || !qosc_is_alnum_uc(server)) return NULL;
  return server;
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

/* server settings or NULL, if server unknown */
static qosc_settings_t *qosc_get_settings(request_rec *r) {
  qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(r->server->module_config,
                                                                      &qos_control_module);
  apr_table_t *qt = qosc_get_query_table(r);
  qosc_settings_t *settings = apr_pcalloc(r->pool, sizeof(qosc_settings_t));
  char *server = apr_pstrdup(r->pool, qosc_get_server(qt));
  settings->server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
  if(!server && (strlen(r->parsed_uri.path) > 4)) {
    if(strcmp(&r->parsed_uri.path[strlen(r->parsed_uri.path)-3], ".do") == 0) {
      server = strrchr(r->parsed_uri.path, '/');
      if(server) {
        struct stat attrib;
        server++;
        server = apr_pstrdup(r->pool, server);
        server[strlen(server)-3] = '\0';
        settings->server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
        if(stat(settings->server_dir, &attrib) != 0) {
          server == NULL;
        }
      }
    }
  }
  if(!server) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"could not determine server name");
    return NULL;
  }
  settings->server = server;
  settings->server_conf = apr_pstrcat(r->pool, settings->server_dir, "/"QOSC_SERVER_CONF, NULL);
  settings->access_log = apr_pstrcat(r->pool, settings->server_dir, "/"QOSC_ACCESS_LOG, NULL);
  settings->status_file = apr_pstrcat(r->pool, settings->server_dir, "/"QOSC_STATUS, NULL);
  settings->running_file = apr_pstrcat(r->pool, settings->server_dir, "/"QOSC_RUNNING, NULL);
  settings->server_options = apr_pstrcat(r->pool, settings->server_dir, "/"QOSC_SERVER_OPTIONS, NULL);
  settings->sconf = sconf;
  settings->qt = qt;
  return settings;
}

static char *qosc_url2filename(apr_pool_t *pool, const char *url) {
  char *u = apr_pstrdup(pool, url);
  char *p = u;
  while(p && p[0]) {
    if(p[0] == '/') p[0] = '_';
    p++;
  }
  return apr_pstrcat(pool, "qs/", u, NULL);
}

static int qosc_fgetline(char *s, int n, FILE *f) {
  register int i = 0;
  s[0] = '\0';
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

static apr_table_t *qosc_file2table(apr_pool_t *pool, const char *filename) {
  apr_table_t *table = apr_table_make(pool, 2);
  FILE *f = fopen(filename, "r");
  if(f) {
    char line[QOSC_HUGE_STRING_LEN];
    while(!qosc_fgetline(line, sizeof(line), f)) {
      apr_table_add(table, line, "");
    }
    fclose(f);
  }
  return table;
}

/* reads a multipart and stores its data in "f"
   only the part with the provided name is stored
   thr regex specifiy which part of each line should be stored */
#ifdef AP_REGEX_H
static apr_status_t qosc_store_multipart(request_rec *r, FILE *f, const char *name, ap_regex_t *regex)
#else
static apr_status_t qosc_store_multipart(request_rec *r, FILE *f, const char *name, regex_t *regex)
#endif
{
  const char *type = apr_table_get(r->headers_in, "content-type");
  char *boundary = strstr(type, "boundary=");
  int seen_eos = 0;
  int write = 0;
  int start = 0;
  char *disp = apr_psprintf(r->pool, "Content-Disposition: form-data; name=\"%s\"", name);

  //  Content-Type: multipart/form-data; boundary=---------------------------21220929591836800491534788240
  if(strstr(type, "multipart/form-data") == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid post (expect multipart/from-data) '%s'", type);
    return !APR_SUCCESS;
  }
  if(boundary == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid post (no boundary) '%s'", type);
    return !APR_SUCCESS;
  }
  boundary = &boundary[strlen("boundary=")];
  do {
    apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_status_t rc = ap_get_brigade(r->input_filters, bb, AP_MODE_GETLINE, APR_BLOCK_READ, 0);
    const char *buf;
    apr_size_t buf_len;
    if (rc != APR_SUCCESS) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOSC_LOG_PFX(0)"could not read client data");
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    while(!APR_BRIGADE_EMPTY(bb) && !seen_eos) {
      apr_bucket *bucket = APR_BRIGADE_FIRST(bb);
      if(APR_BUCKET_IS_EOS(bucket)) {
        seen_eos = 1;
      } else if(APR_BUCKET_IS_FLUSH(bucket)) {
        /* do nothing */
      } else {
        rc = apr_bucket_read(bucket, &buf, &buf_len, APR_BLOCK_READ);
        if (rc != APR_SUCCESS) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, 
                        QOSC_LOG_PFX(0)"could not read client data");
          return HTTP_INTERNAL_SERVER_ERROR;
        }
        {
          apr_pool_t *lpool;
          char *tmp_buf_p;
          apr_pool_create(&lpool, r->pool);
          tmp_buf_p = apr_psprintf(lpool, "%.*s", buf_len, buf);
          while(strchr(tmp_buf_p, QOSLF) == NULL) {
            APR_BUCKET_REMOVE(bucket);
            bucket = APR_BRIGADE_FIRST(bb);
            if(APR_BUCKET_IS_EOS(bucket)) {
              seen_eos = 1;
            } else if(APR_BUCKET_IS_FLUSH(bucket)) {
              /* do nothing */
            } else {
              apr_bucket_read(bucket, &buf, &buf_len, APR_BLOCK_READ);
              tmp_buf_p = apr_psprintf(lpool, "%s%.*s", tmp_buf_p, buf_len, buf);
              if(seen_eos) break;
            }
          }
          if(!write && ap_strcasestr(tmp_buf_p, disp)) {
            write = 1;
            start = 0;
          }
          if(write) {
            if(start < 2) {
              if(ap_strcasestr(tmp_buf_p, "Content-Type") == NULL) {
                start++;
              }
            } else {
              if(strstr(tmp_buf_p, boundary)) {
                write = 0;
                start = 0;
              } else {
                if(regex) {
                  ap_regmatch_t ma;
                  if(ap_regexec(regex, tmp_buf_p, 1, &ma, 0) == 0) {
                    char m[ma.rm_eo - ma.rm_so + 1];
                    char *m_start;
                    char *m_end;
                    strncpy(m, &tmp_buf_p[ma.rm_so], ma.rm_eo - ma.rm_so);
                    m[ma.rm_eo - ma.rm_so] = '\0';
                    m_start = strchr(m, ' ');
                    while(m_start[0] == ' ') m_start++;
                    m_end = strrchr(m, ' ');
                    m_end[0] = '\0';
                    fprintf(f, "%s\n", m_start);
                    fflush(f);
                  }
                } else {
                  if(tmp_buf_p[1] && tmp_buf_p[strlen(tmp_buf_p)-2] == QOSCR) {
                    tmp_buf_p[strlen(tmp_buf_p)-2] = QOSLF;
                    tmp_buf_p[strlen(tmp_buf_p)-1] = '\0';
                  }
                  fprintf(f, "%s", tmp_buf_p);
                  fflush(f);
                }
              }
            }
          }
          apr_pool_destroy(lpool);
        }
      }
      APR_BUCKET_REMOVE(bucket);
    }
    apr_brigade_destroy(bb);
  } while(!seen_eos);
  return APR_SUCCESS;
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
  a:active  { color:black; text-decoration:underline; }\n\
  form      { display: inline; }\n", r);
}

static qosc_append_file(apr_pool_t *pool, const char *dest, const char *source) {
  FILE *ds = fopen(dest, "a");
  FILE *sr = fopen(source, "r");
  if(sr && ds) {
    char line[QOSC_HUGE_STRING_LEN];
    while(!qosc_fgetline(line, sizeof(line), sr)) {
      fprintf(ds, "%s\n", line);
    }
  }
  if(ds) fclose(ds);
  if(sr) fclose(sr);
}

/* get the path of the current request */
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

/* redirect using javascript */
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

/* creates a new server instance */
static void qosc_create_server(request_rec *r, qosc_settings_t *settings) {
  const char *action = apr_table_get(settings->qt, "action");
  const char *qs = apr_pstrcat(r->pool, settings->server_dir, "/qs", NULL);
  if((strcmp(settings->server, "ct") == 0) ||
     (strcmp(settings->server, "qsfilter2") == 0) ||
     (strcmp(settings->server, "download") == 0)) {
    ap_rputs("Invalid server name.", r);
  } else {
    if((action == NULL) || ((strcmp(action, "add") != 0) && (strcmp(action, "set") != 0))) {
      ap_rputs("Unknown action.", r);
    } else {
      if(strcmp(action, "set") == 0) {
        char *conf = (char *)apr_table_get(settings->qt, "conf");
        FILE *f = NULL;
        if(conf) {
          conf = apr_pstrdup(r->pool, conf);
          qosc_unescaping(conf);
          f = fopen(conf, "r");
          if(f) {
            if(mkdir(settings->server_dir, 0750) != 0) {
              ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                            QOSC_LOG_PFX(0)"failed to create directory '%s'", settings->server_dir);
              ap_rprintf(r, "Failed to create directory '%s'", settings->server_dir);
              fclose(f);
              f=NULL;
              return;
            } else {
              FILE *c = fopen(settings->server_conf, "w");
              mkdir(qs, 0750);
              if(c) {
                fprintf(c, "conf=%s\n", conf);
                fclose(c);
              }
              c = fopen(settings->server_options, "w");
              if(c) {
                fprintf(c, "-m\n");
                fclose(c);
              }
            }
          }
        } else {
          if(r->method_number == M_POST) {
            struct stat attrib;
            char *httpdconf;
            if(stat(settings->server_dir, &attrib) != 0) {
              if(mkdir(settings->server_dir, 0750) != 0) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                              QOSC_LOG_PFX(0)"failed to create directory '%s'", settings->server_dir); 
                ap_rprintf(r, "Failed to create directory '%s'", settings->server_dir);
                return;
              }
            }
            httpdconf = apr_pstrcat(r->pool, settings->server_dir, "/httpd.conf", NULL);
            mkdir(qs, 0750);
            f = fopen(httpdconf, "w");
            if(f) {
              apr_status_t status = qosc_store_multipart(r, f, "httpd_conf", NULL);
              if(status != APR_SUCCESS) {
                fclose(f);
                f=NULL;
                unlink(httpdconf);
                unlink(qs);
                unlink(settings->server_dir);
              } else {
                FILE *c = fopen(settings->server_conf, "w");
                mkdir(apr_pstrcat(r->pool, settings->server_conf, "/qs", NULL), 0750);
                if(c) {
                  fprintf(c, "conf=%s\n", httpdconf);
                  fclose(c);
                }
                c = fopen(settings->server_options, "w");
                if(c) {
                  fprintf(c, "-m\n");
                  fclose(c);
                }
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
          qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server,
                                          ".do?action=load", NULL));
          fclose(f);
        }
      }
      if(strcmp(action, "add") == 0) {
        char *w = apr_pstrcat(r->pool, settings->sconf->path, "/", settings->server, NULL);
        DIR *dir = opendir(w);
        ap_rputs("<table class=\"btable\"><tbody>\n",r);
        if(!dir){ 
          ap_rputs("<tr class=\"rows\"><td>\n",r);
          ap_rprintf(r, "<form action=\"%sct.do\" method=\"get\">\n",
                     qosc_get_path(r));
          ap_rprintf(r, "Specify the server configuration file (httpd.conf) for '%s':<br>\n"
                     "&nbsp;<input name=\"conf\" value=\"&lt;path&gt;\" type=\"text\" size=\"50\">\n"
                     " <input name=\"server\" value=\"%s\"    type=\"hidden\">\n"
                     " <input name=\"action\" value=\"set\" type=\"submit\">\n"
                     " </form>\n", ap_escape_html(r->pool, settings->server),
                     ap_escape_html(r->pool, settings->server));
          ap_rputs("</td></tr>\n",r);
          ap_rputs("<tr class=\"rows\"><td>\n",r);

          ap_rputs("Upload a httpd.conf file:<br>", r);
          ap_rprintf(r, "<form action=\"%sct.do?server=%s&action=set\""
                     " method=\"post\" enctype=\"multipart/form-data\">\n",
                     qosc_get_path(r), ap_escape_html(r->pool, settings->server));
          ap_rprintf(r, "&nbsp;<input name=\"httpd_conf\" value=\"\" type=\"file\" size=\"50\">\n"
                     " <input name=\"action\" value=\"upload\" type=\"submit\">\n"
                     " </form>\n", ap_escape_html(r->pool, settings->server));
          ap_rputs("</td></tr>\n",r);
        } else {
          closedir(dir);
          ap_rprintf(r, "Server '%s' already exists.",
                     ap_escape_html(r->pool, settings->server));
        }
        ap_rputs("</tbody></table>\n", r);
      }
    }
  }
}

/* reads the configuration value of the specified directive (e.g. "QS_PermitUri ") */
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
  if(v && (strlen(v) > 2)) {
    if(v[0] == '"') {
      if(v[strlen(v)-1] == '"') {
        v++;
        v[strlen(v)-1] = '\0';
      }
    }
  }
  return v;
}

static void qosc_close_locations(apr_table_t *locations, int delete) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(locations)->elts;
  for(i = 0; i < apr_table_elts(locations)->nelts; i++) {
    qosc_location_t *l = (qosc_location_t *)entry[i].val;
    if(l->fd) {
      fclose(l->fd);
      l->fd = 0;
    }
    if(delete) {
      unlink(l->name);
    }
  }
}

static void qosc_reopen_locations(apr_table_t *locations, const char *mode) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(locations)->elts;
  for(i = 0; i < apr_table_elts(locations)->nelts; i++) {
    qosc_location_t *l = (qosc_location_t *)entry[i].val;
    if(l->fd == 0) {
      l->fd = fopen(l->name, mode);
    }
  }
}

/* loads a list of all locations from the configuration and opens the file containing
   all urls to this location */
static apr_table_t *qosc_read_locations(request_rec *r, const char *server_dir,
                                        const char *server_conf, int init) {
  FILE *f = fopen(server_conf, "r");
  apr_table_t *locations = apr_table_make(r->pool, 2);
  if(f) {
    char line[QOSC_HUGE_STRING_LEN];
    while(!qosc_fgetline(line, sizeof(line), f)) {
      if(strncmp(line, "location=", strlen("location=")) == 0) {
        char *loc = apr_pstrdup(r->pool, &line[strlen("location=")]);
        qosc_location_t *l = apr_pcalloc(r->pool, sizeof(qosc_location_t));
        l->uri = apr_pstrdup(r->pool, loc);
        l->name = apr_pstrcat(r->pool, server_dir, "/", qosc_url2filename(r->pool, loc), ".loc", NULL);
        if(apr_table_get(locations, loc) == NULL) {
          if(init) {
            l->fd = fopen(l->name, "w");
            unlink(apr_pstrcat(r->pool, l->name, ".url_deny_new", NULL));
            unlink(apr_pstrcat(r->pool, l->name, ".rules", NULL));
            unlink(apr_pstrcat(r->pool, l->name, ".rep", NULL));
          } else {
            l->fd = fopen(l->name, "r");
          }
          if(!l->fd) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          QOSC_LOG_PFX(0)"could not open '%s'", l->name);
            qosc_close_locations(locations, 0);
            return NULL;
          }
          apr_table_setn(locations, loc, (char *)l);
          fclose(l->fd);
          l->fd = 0;
          qosc_append_file(r->pool, l->name, apr_pstrcat(r->pool, l->name, ".url_permit", NULL));
        }
      }
    }
    {
      /* used for unknown locations */
      char *loc = apr_pstrdup(r->pool, "404");
      qosc_location_t *l = apr_pcalloc(r->pool, sizeof(qosc_location_t));
      l->uri = loc;
      l->name = apr_pstrcat(r->pool, server_dir, "/qs/404.loc", NULL);
      if(init) {
        l->fd = fopen(l->name, "w");
        unlink(apr_pstrcat(r->pool, l->name, ".url_deny_new", NULL));
      } else {
        l->fd = fopen(l->name, "r");
      }
      apr_table_setn(locations, loc, (char *)l);
      fclose(l->fd);
      l->fd = 0;
      qosc_append_file(r->pool, l->name, apr_pstrcat(r->pool, l->name, ".url_permit", NULL));
    }
    fclose(f);
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"could not open server configuration '%s'", server_conf);
  }
  return locations;
}

/* returns the best matching location */
static const char *qosc_get_location_match(apr_table_t *locations, const char *uri) {
  int len = 0;
  const char *location = NULL;
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(locations)->elts;
  for(i = 0; i < apr_table_elts(locations)->nelts; i++) {
    if((strncmp(uri, entry[i].key, strlen(entry[i].key)) == 0) &&
       (strlen(entry[i].key) > len)) {
      len = strlen(entry[i].key);
      location = entry[i].key;
    }
  }
  return location;
}

/* returns the httpd.conf path */
static char *qosc_get_httpd_conf_name(request_rec *r, qosc_settings_t *settings) {
  FILE *f = fopen(settings->server_conf, "r");
  char *httpdconf = NULL;
  if(f) {
    char line[QOSC_HUGE_STRING_LEN];
    line[0] = '\0';
    qosc_fgetline(line, sizeof(line), f);
    if(line[0]) {
      httpdconf = apr_pstrdup(r->pool, line);
      if(strncmp(httpdconf, "conf=", strlen("conf=")) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOSC_LOG_PFX(0)"invalid server settings '%s'", httpdconf);
        httpdconf = NULL;
      } else {
        httpdconf = httpdconf + strlen("conf=");
      }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOSC_LOG_PFX(0)"invalid server settings");
    }
    fclose(f);
  } else {  
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"failed to open configuration file '%s'", settings->server_conf);
  }
  return httpdconf;
}

/* returns a list of log files defined by configuration (httpd.conf) which
   are available on this server (local fs) */
static apr_table_t *qosc_read_logfile(request_rec *r, const char *server_conf) {
  FILE *f = fopen(server_conf, "r");
  apr_table_t *logs = apr_table_make(r->pool, 2);
  if(f) {
    char line[QOSC_HUGE_STRING_LEN];
    while(!qosc_fgetline(line, sizeof(line), f)) {
      if(strncmp(line, "log=", strlen("log=")) == 0) {
        char *log = apr_pstrdup(r->pool, &line[strlen("log=")]);
        FILE *l = fopen(log, "r");
        if(l) {
          apr_table_set(logs, log, "");
          fclose(l);
        }
      }
    }
    fclose(f);
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"could not open server configuration");
  }
  return logs;
}

//static int qosc_insert2location(request_rec *r, const char *server_dir, const char *server_conf,
//                                apr_table_t *rules, const char *url, const char *filter) {
//  char *httpdconf = qosc_get_httpd_conf_name(r, settings);
//  char *root = apr_pstrdup(r->pool, httpdconf);
//  char *p = strrchr(root, '/');
//  if(p) p[0] = '\0';

//  char *tmp_file = apr_pstrcat(r->pool, server_conf, ".tmp", NULL);
//  char *directive = apr_pstrcat(r->pool, filter, " ", NULL);
//  FILE *in = fopen(server_conf, "r");
//  FILE *out = fopen(tmp_file, "r");
//  char line[QOSC_HUGE_STRING_LEN];
//  if(in) {
//    while(!qosc_fgetline(line, sizeof(line), f)) {
//      const char *inc = qosc_get_conf_value(line, "Include ");
//      const char *loc = qosc_get_conf_value(line, "Location ");
//      const char *permit = qosc_get_conf_value(line, directive);
//      if(inc) {
//        /* server MUST use relative includes only!
//         *  root=/etc/apache/conf
//         *  inc=conf/sub.conf
//         */
//        char *search = apr_pstrdup(r->pool, inc);
//        char *fl = strchr(search, '/');
//        char *base = apr_pstrdup(r->pool, root);
//        char *e;
//        if(fl) {
//          fl[0] = '\0';
//          fl++;
//        }
//        e = strstr(base, search);
//        if(e && fl) {
//          char *incfile;
//          e[strlen(search)] = '\0';
//          incfile = apr_pstrcat(r->pool, base, "/", fl, NULL);
//          qosc_insert2location(r, server_dir, incfile, root, st, errors);
//
//$$$$$$$$$$$$$$$$$$$$$
//static int qosc_insert2location(request_rec *r, const char *server_conf,
//                                apr_table_t *rules, const char *url, const char *filter) {
//
//
//        } else {
//          errors++;
//          ap_rprintf(r, "Failed to resolve '%s'.<br>\n", ap_escape_html(r->pool, line));
//          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
//                        QOSC_LOG_PFX(0)"failed to find included httpd configuration file '%s'",
//                        line);
//        }
//      }
//      if(loc) {
//        char *end = (char *)loc;
//        char *filename;
//        while(end[0] && (end[0] != ' ') && (end[0] != '>') && (end[0] != '\t')) end++;
//        end[0] = '\0';
//      }
//
//    }
//    fclose(in);
//    fclose(out);
//  } else {
//    fclose(out);
//  }
//
//
//  return APR_SUCCESS;
//}

static char *qosc_included_file_path(request_rec *r, const char *root, const char *include) {
  char *path = NULL;
  /* server MUST use relative includes only!
   *  root=/etc/apache/conf
   *  inc=conf/sub.conf
   */
  char *search = apr_pstrdup(r->pool, include);
  char *fl = strchr(search, '/');
  char *base = apr_pstrdup(r->pool, root);
  char *e;
  if(fl) {
    fl[0] = '\0';
    fl++;
  }
  e = strstr(base, search);
  if(e && fl) {
    e[strlen(search)] = '\0';
    path = apr_pstrcat(r->pool, base, "/", fl, NULL);
  }
  return path;
}

static void qosc_load_httpdconf(request_rec *r, const char *server_dir, 
                                const char *file, const char *root, STACK *st, int *errors) {
  FILE *f = fopen(file, "r");
  FILE *fp = 0;
  FILE *fd = 0;
  char line[QOSC_HUGE_STRING_LEN];
  if(f) {
    while(!qosc_fgetline(line, sizeof(line), f)) {
      const char *inc = qosc_get_conf_value(line, "Include ");
      const char *host = qosc_get_conf_value(line, "VirtualHost ");
      const char *loc = qosc_get_conf_value(line, "Location ");
      const char *tr = qosc_get_conf_value(line, "TransferLog ");
      const char *permit = qosc_get_conf_value(line, "QS_PermitUri ");
      const char *deny = qosc_get_conf_value(line, "QS_DenyRequestLine ");
      if(inc) {
        char *incfile = qosc_included_file_path(r, root, inc);
        if(incfile) {
          qosc_load_httpdconf(r, server_dir, incfile, root, st, errors);
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
        char *filename;
        while(end[0] && (end[0] != ' ') && (end[0] != '>') && (end[0] != '\t')) end++;
        end[0] = '\0';
        sk_push(st, apr_pstrcat(r->pool, "location=", loc, NULL));
        if(fp) fclose(fp);
        if(fd) fclose(fd);
        filename = qosc_url2filename(r->pool, loc);
        fp = fopen(apr_pstrcat(r->pool, server_dir, "/", filename, ".loc.permit", NULL), "w");
        fd = fopen(apr_pstrcat(r->pool, server_dir, "/", filename, ".loc.deny", NULL), "w");
      }
      if(host) {
        char *end = (char *)host;
        while(end[0] && (end[0] != ' ') && (end[0] != '>') && (end[0] != '\t')) end++;
        end[0] = '\0';
        sk_push(st, apr_pstrcat(r->pool, "host=", host, NULL));
      }
      if(tr) {
        if(strchr(tr, '|')) {
          char *end;
          tr = strchr(tr, '|');
          while(tr[0] && (tr[0] != ' ') && (tr[0] != '\t')) tr++;
          while(tr[0] && (tr[0] != '/')) tr++;
          end = (char *)tr;
          while(end[0] && (end[0] != ' ') && (end[0] != '\t')) end++;
          end[0] = '\0';
        }
        sk_push(st, apr_pstrcat(r->pool, "log=", tr, NULL));
      }
      if(permit) {
        sk_push(st, apr_pstrcat(r->pool, "QS_PermitUri=", permit, NULL));
        if(fp) {
          fprintf(fp, "QS_PermitUri %s\n", permit);
        }
      }
      if(deny) {
        sk_push(st, apr_pstrcat(r->pool, "QS_DenyRequestLine=", deny, NULL));
        if(fd) {
          fprintf(fd, "QS_DenyRequestLine %s\n", deny);
        }
      }
    }
    fclose(f);
    if(fp) fclose(fp);
    if(fd) fclose(fd);
  } else {
    errors++;
    ap_rprintf(r, "Failed to open '%s'.<br>\n", ap_escape_html(r->pool, file));
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"failed to open httpd configuration file '%s'", file); 
  }
}

static void qosc_server_load(request_rec *r, qosc_settings_t *settings) {
  FILE *f;
  int errors = 0;
  STACK *st = sk_new(NULL);
  char *httpdconf = qosc_get_httpd_conf_name(r, settings);
  char *root = apr_pstrdup(r->pool, httpdconf);
  char *p = strrchr(root, '/');
  if(p) p[0] = '\0';
  sk_push(st, apr_pstrcat(r->pool, "conf=", httpdconf, NULL));
  qosc_load_httpdconf(r, settings->server_dir, httpdconf, root, st, &errors);
  f = fopen(settings->server_conf, "w");
  if(f) {
    int i;
    for(i = 0; i < sk_num(st); i++) {
      char *l = sk_value(st, i);
      fprintf(f, "%s\n", l);
    }
    fclose(f);
  } else {
    errors++;
    ap_rprintf(r, "Failed to write '%s'.<br>\n", ap_escape_html(r->pool, settings->server_conf));
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"failed to write to '%s'", settings->server_conf);
  }
  sk_free(st);
  if(errors == 0) {
    qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server, ".do", NULL));
  }
}

/* used to upload an access log file */
static void qosc_qsfilter2_upload(request_rec *r, qosc_settings_t *settings) {
  const char *action = apr_table_get(settings->qt, "action");
  const char *type = apr_table_get(r->headers_in, "content-type");
  if((r->method_number != M_POST) || !action || !type) {
    ap_rputs("Invalid request.", r);
    return;
  }
  if(strcmp(action, "upload") == 0) {
    /* receives an access log file */
    FILE *f = fopen(settings->access_log, "w");
    if(!f) {
      ap_rprintf(r, "Failed to write '%s'.<br>\n", ap_escape_html(r->pool, settings->access_log));
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOSC_LOG_PFX(0)"failed to write to '%s'", settings->access_log);
    } else {
#ifdef AP_REGEX_H
      ap_regex_t *regex = ap_pregcomp(r->pool, QOSC_REQ, AP_REG_EXTENDED);
#else
      regex_t *regex = ap_pregcomp(r->pool, QOSC_REQ, REG_EXTENDED);
#endif
      apr_status_t status;
      if(regex == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOSC_LOG_PFX(0)"failed to compile regex '%s'", QOSC_REQ);
      } else {
        status = qosc_store_multipart(r, f, "access_log", regex);
        unlink(settings->status_file);
      }
      fclose(f);
    }
    qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server,
                                    ".do?action=qsfilter2", NULL));
  } else {
    ap_rputs("Unknown action.", r);
    return;
  }
}

/* determines the log file name from the QOSC_STATUS file (by line number) */
static char *qosc_locfile_id2name(request_rec *r, int line_number, int file) {
  qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  apr_table_t *qt = qosc_get_query_table(r);
  const char *server = qosc_get_server(qt);
  char *server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
  char *status_file = apr_pstrcat(r->pool, server_dir, "/"QOSC_STATUS, NULL);
  FILE *fs;
  char *file_name = NULL;
  char *url = NULL;
  if(!server) {
    return NULL;
  }
  if(line_number == 0) {
    return NULL;
  }
  fs = fopen(status_file, "r");
  if(fs) {
    int i = 0;
    char line[QOSC_HUGE_STRING_LEN];
    while(!qosc_fgetline(line, sizeof(line), fs)) {
      if(i == line_number) {
        char *end = strchr(line, ' ');
        if(end) {
          end[0] = '\0';
          file_name = apr_pstrcat(r->pool, line, NULL);
          end++;
          while(end[0] && (end[0] != ' ')) end++;
          while(end[0] && (end[0] == ' ')) end++;
          url = end;
        }
        break;
      }
      i++;
    }
    fclose(fs);
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"could not open status file '%s'", status_file);
    return NULL;
  }
  if(file) {
    return file_name;
  }
  return url;
}

static int qosc_create_input_configuration(request_rec *r, const char *location) {
  char *dest = apr_pstrcat(r->pool, location, ".conf", NULL);
  FILE *df = fopen(dest, "w");
  if(df) {
    fclose(df);
    // permit rules from server conf
    qosc_append_file(r->pool, dest, apr_pstrcat(r->pool, location, ".permit", NULL));
    // deny rules from server conf
    qosc_append_file(r->pool, dest, apr_pstrcat(r->pool, location, ".deny", NULL));
    // control rules (blacklist, custom rules)
    {
      FILE *f = fopen(apr_pstrcat(r->pool, location, ".url_deny", NULL), "r");
      if(f) {
        char line[QOSC_HUGE_STRING_LEN];
        df = fopen(dest, "a");
        while(!qosc_fgetline(line, sizeof(line), f)) {
          char *data;
          qosc_unescaping(line);
          data = qosc_pcre_escape(r->pool, line);
          fprintf(df, "QS_DenyRequestLine -restrict deny \"%s\"\n", data);
        }
        fclose(df);
        fclose(f);
      }
    }
  }
  return 0;
}

static void qosc_qsfilter2_execute(request_rec *r, apr_table_t *locations,
                                   const char *running_file, const char *status_file) {
  qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  apr_table_t *qt = qosc_get_query_table(r);
  const char *server = qosc_get_server(qt);
  char *server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
  char *server_options = apr_pstrcat(r->pool, server_dir, "/"QOSC_SERVER_OPTIONS, NULL);
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(locations)->elts;
  FILE *f = fopen(status_file, "w");
  time_t now = time(NULL);
  char tmb[128];
  struct tm *ptr = localtime(&now);
  strftime(tmb, sizeof(tmb), "%H:%M:%S %d.%m.%Y", ptr);
  if(f) {
    fprintf(f, "%s\n", tmb);
  }
  for(i = 0; i < apr_table_elts(locations)->nelts; i++) {
    qosc_location_t *l = (qosc_location_t *)entry[i].val;
    char *cmd;
    int status = 0;
    struct stat attrib;
    FILE *fr;
    FILE *fo = fopen(server_options, "r");
    char *query_option = "";
    if(fo) {
      char line[QOSC_HUGE_STRING_LEN];
      qosc_fgetline(line, sizeof(line), fo);
      if(strlen(line) > 0) {
        query_option = apr_pstrdup(r->pool, line);
      }
      fclose(fo);
    }
    qosc_create_input_configuration(r, l->name);
    cmd = apr_psprintf(r->pool, "%s %s -i %s -c %s.conf -e >%s.rep 2>%s.err",
                       sconf->qsfilter2,
                       query_option,
                       l->name, l->name,
                       l->name, l->name);
    fr = fopen(running_file, "a");
    if(fr) {
      fprintf(fr, "<li>process %s\n",
              ap_escape_html(r->pool, l->uri));
      fflush(fr);
      fclose(fr);
    }
    if((stat(l->name, &attrib) == 0) && (attrib.st_size > 0)) {
      status = system(cmd);
      if(f) {
        fprintf(f, "%s %d %s\n",l->name, status, l->uri);
      }
    }
    fr = fopen(running_file, "a");
    if(fr) {
      fprintf(fr, " - %s</li>\n", status == 0 ? "done" : "<b>failed</b>");
      fflush(fr);
      fclose(fr);
    }
  }
  if(f) {
    fclose(f);
  }
}

static void qosc_qsfilter2_sort(request_rec *r, apr_table_t *locations,
                                const char *running_file, const char *access_log) {
  FILE *ac;
  FILE *fr = fopen(running_file, "w");
  if(fr) {
    fprintf(fr, "<li>sort access log data\n");
    fflush(fr);
    fclose(fr);
  }
  ac = fopen(access_log, "r");
  if(ac) {
    char line[QOSC_HUGE_STRING_LEN];
    while(!qosc_fgetline(line, sizeof(line), ac)) {
      const char *loc = qosc_get_location_match(locations, line);
      qosc_location_t *l = (qosc_location_t *)apr_table_get(locations, loc);
      if(l == NULL) l = (qosc_location_t *)apr_table_get(locations, "404");
      if(l) {
        fprintf(l->fd, "%s\n", line);
      } else {
        qosc_log(r->pool, "no location found for '%s'", line);
      }
    }
  } else {
    qosc_log(r->pool, "failed to open '%s' (%s)", access_log, strerror(errno));
  }
  fr = fopen(running_file, "a");
  if(fr) {
    fprintf(fr, " - done</li>\n");
    fflush(fr);
    fclose(fr);
  }
}

static void qosc_qsfilter2_start(request_rec *r, qosc_settings_t *settings) {
  apr_table_t *locations = qosc_read_locations(r, settings->server_dir, settings->server_conf, 1);
  if(locations == NULL) {
    ap_rprintf(r, "Unable to process data.");
  } else {
    struct stat attrib;
    if(stat(settings->access_log, &attrib) == 0) {
      int i;
      pid_t pid;
      int status;
      FILE *fr = fopen(settings->running_file, "w");
      if(fr) fclose(fr);
      /*
       * well, we seem to be ready to start data processing
       * no "return" after this line...
       */
      qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server,
                                      ".do?action=qsfilter2", NULL));
      switch (pid = fork()) {
      case -1:
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                      QOSC_LOG_PFX(0)"failed to fork process");
        return;
      case 0:
        /* this child must return (it's in the scoreboard) */
        switch (pid = fork()) {
        case -1:
          ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                        QOSC_LOG_PFX(0)"failed to fork process");
          return;
        case 0:
          /* child processing the data */
          for(i=3;i<65000;i++) {
            /* $$$ */
            close(i);
          }
          qosc_reopen_locations(locations, "a");
          qosc_qsfilter2_sort(r, locations, settings->running_file, settings->access_log);
          qosc_close_locations(locations, 0);
          qosc_qsfilter2_execute(r, locations, settings->running_file, settings->status_file);
          status = unlink(settings->running_file);
          if(status != 0) {
            qosc_log(r->pool,"could remove status file '%s' (%s)",
                     settings->running_file, strerror(errno));
          }
          exit(0);
        default:
          exit(0);
        }
      default:
        /* suppress "long lost child came home!" */
        waitpid(pid, &status, 0);
      }
    } else {
      ap_rprintf(r, "Could not open access log data.");
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOSC_LOG_PFX(0)"could not open access log data '%s'", settings->access_log);
    }
  }
  return;
}

static void qosc_qsfilter2_saveoptions(request_rec *r, qosc_settings_t *settings) {
  const char *query = apr_table_get(settings->qt, "query");
  const char *path = apr_table_get(settings->qt, "path");
  FILE *f;
  if(!query) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no query parameter");
    return;
  }
  f = fopen(settings->server_options, "w");
  if(f) {
    char *path_option = "";
    if(path && strstr(path, "-h")) {
      path_option = apr_pstrdup(r->pool, " -h");
    }
    if(strstr(query, "-m") != NULL) {
      fprintf(f, "-m%s\n", path_option);
    } else  if(strstr(query, "-p") != NULL) {
      fprintf(f, "-p%s\n", path_option);
    } else if(strstr(query, "-s") != NULL) {
      fprintf(f, "-s%s\n", path_option);
    } else {
      fprintf(f, "%s\n", path_option);
    }
    fclose(f);
  }
  qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server,
                                  ".do?action=qsfilter2", NULL));
}

static void qosc_qsfilter2_permitdeny(request_rec *r, qosc_settings_t *settings) {
  const char *loc = apr_table_get(settings->qt, "loc");
  const char *url = apr_table_get(settings->qt, "url");
  const char *action = apr_table_get(settings->qt, "action");
  char *file_name = NULL;
  if(!loc) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no location file");
    return;
  }
  if(!url) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no url number");
    return;
  }
  file_name = apr_pstrcat(r->pool, qosc_locfile_id2name(r, atoi(loc), 1), ".rep", NULL);
  if(file_name && file_name[0]) {
    FILE *f = fopen(file_name, "r");
    if(f) {
      char *search = apr_pstrcat(r->pool, "# ADD line ", url, ": ", NULL);
      char line[QOSC_HUGE_STRING_LEN];
      while(!qosc_fgetline(line, sizeof(line), f)) {
        if(strncmp(line, search, strlen(search)) == 0) {
          char *u = &line[strlen(search)];
          FILE *fp;
          // cut .rep
          file_name[strlen(file_name) - 4] = '\0';
          if(strcmp(action, "permit") == 0) {
            fp = fopen(apr_pstrcat(r->pool, file_name, ".url_permit", NULL), "a");
          } else {
            FILE *fd = fopen(apr_pstrcat(r->pool, file_name, ".url_deny_new", NULL), "w");
            fclose(fd);
            fp = fopen(apr_pstrcat(r->pool, file_name, ".url_deny", NULL), "a");
          }
          if(fp) {
            fprintf(fp, "%s\n", u);
            fclose(fp);
          }
          qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server,
                                          ".do?action=qsfilter2#", loc, NULL));
          break;
        }
      }
      fclose(f);
    }
  } else {
    ap_rprintf(r, "Invalid request.");
    return;
  }
}

static void qosc_qsfilter2_store(request_rec *r, qosc_settings_t *settings) {
  const char *loc = apr_table_get(settings->qt, "loc");
  const char *action = apr_table_get(settings->qt, "action");
  struct stat attrib;
  char *file_name;
  char *filter = "QS_PermitUri";
  apr_table_t *rules = apr_table_make(r->pool, 10);
  char *location;
  char *dedicated_rules;
  if(!loc) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no location file");
    return;
  }
  if(!action) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no action");
    return;
  }
  location = qosc_locfile_id2name(r, atoi(loc), 1);
  dedicated_rules = apr_pstrcat(r->pool, location, ".rules", NULL);
  if(stat(dedicated_rules, &attrib) == 0) {
    file_name = apr_pstrcat(r->pool, location, ".rules", NULL);
    //    filter = NULL;
  } else {
    file_name = apr_pstrcat(r->pool, location, ".rep", NULL);
  }
  if(file_name && file_name[0]) {
    FILE *f = fopen(file_name, "r");
    if(f) {
      char line[QOSC_HUGE_STRING_LEN];
      char *url = qosc_locfile_id2name(r, atoi(loc), 0);
      while(!qosc_fgetline(line, sizeof(line), f)) {
        if(filter) {
          if(strncmp(line, filter, strlen(filter)) == 0) {
            apr_table_set(rules, line, "");
          }
        } else {
          apr_table_set(rules, line, "");
        }
      }        
      fclose(f);
      //      fprintf(stderr, "%s\n", url); fflush(stderr);
      //      qosc_insert2location(r, server_dir, server_conf, rules, url, filter);
    } else {
      ap_rprintf(r, "Could not read rule file.");
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOSC_LOG_PFX(0)"could not open file '%s'", file_name);
      return;
    }
  } else {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"could determine file name");
    return;
  }
    ap_rprintf(r, "Not yet available.");
    /*$$$
  qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server,
                                  ".do?action=qsfilter2#", loc, NULL));
    */
}

static void qosc_qsfilter2_edit(request_rec *r, qosc_settings_t *settings) {
  const char *loc = apr_table_get(settings->qt, "loc");
  const char *action = apr_table_get(settings->qt, "action");
  if(!loc) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no location file");
    return;
  }
  if(!action) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no action");
    return;
  }
  if(strcmp(action, "edit") == 0) {
    char *location = qosc_locfile_id2name(r, atoi(loc), 1);
    char *dedicated_rules = apr_pstrcat(r->pool, location, ".rules", NULL);
    char *file_name;
    char *filter = "QS_PermitUri";
    struct stat attrib;
    if(stat(dedicated_rules, &attrib) == 0) {
      file_name = apr_pstrcat(r->pool, location, ".rules", NULL);
      //filter = NULL;
    } else {
      file_name = apr_pstrcat(r->pool, location, ".rep", NULL);
    }
    if(file_name && file_name[0]) {
      FILE *f = fopen(file_name, "r");
      if(f) {
        char line[QOSC_HUGE_STRING_LEN];
        ap_rprintf(r, "&nbsp;<form action=\"%sqsfilter2.do?action=save&loc=%s&server=%s\" "
                   "method=\"post\" enctype=\"multipart/form-data\">\n",
                   qosc_get_path(r), loc, settings->server);
        ap_rprintf(r, " <input name=\"server\" value=\"%s\" type=\"hidden\">\n",
                   ap_escape_html(r->pool, settings->server));
        ap_rprintf(r, " <input name=\"loc\" value=\"%d\" type=\"hidden\">\n",
                   loc);
        ap_rputs("<textarea name=\"rules\" cols=\"90\" rows=\"20\">", r);
        while(!qosc_fgetline(line, sizeof(line), f)) {
          if(filter) {
            if(strncmp(line, filter, strlen(filter)) == 0) {
              ap_rprintf(r, "%s\n", ap_escape_html(r->pool, line));
            }
          } else {
            ap_rprintf(r, "%s\n", ap_escape_html(r->pool, line));
          }
        }        
        ap_rputs("</textarea>\n", r);
        ap_rprintf(r, "<br><input name=\"action\" value=\"save\" type=\"submit\">\n"
                   " </form>\n");
        fclose(f);
      }
    }
  } else if((strcmp(action, "save") == 0) && (r->method_number == M_POST)) {
    char *file_name = apr_pstrcat(r->pool, qosc_locfile_id2name(r, atoi(loc), 1), ".rules", NULL);
    FILE *f = fopen(file_name, "w");
    if(f) {
      apr_status_t status = qosc_store_multipart(r, f, "rules", NULL);
      fclose(f);
      qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server,
                                      ".do?action=qsfilter2#", loc, NULL));
    } else {
      ap_rprintf(r, "Could not write data.");
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOSC_LOG_PFX(0)"could not write '%s'", file_name);
    }
  } else {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, unknown action for qsfilter2 edit");
    return;
  }
}

static void qosc_qsfilter2_report(request_rec *r, qosc_settings_t *settings) {
  const char *loc = apr_table_get(settings->qt, "loc");
  char *file_name = NULL;
  if(!loc) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no location file");
    return;
  }
  file_name = apr_pstrcat(r->pool, qosc_locfile_id2name(r, atoi(loc), 1), ".rep", NULL);
  if(file_name && file_name[0]) {
    FILE *f = fopen(file_name, "r");
    if(f) {
      char line[QOSC_HUGE_STRING_LEN];
      while(!qosc_fgetline(line, sizeof(line), f)) {
        ap_rprintf(r, "<code>%s</code><br>\n", ap_escape_html(r->pool, line));
      }        
      fclose(f);
    }
  } else {
    ap_rprintf(r, "Invalid request.");
    return;
  }

}

/* imports a local stored access log file */
static void qosc_qsfilter2_import(request_rec *r, qosc_settings_t *settings) {
  const char *file = apr_table_get(settings->qt, "file");
  apr_table_t *logt = qosc_read_logfile(r, settings->server_conf);
  char *logfile;
  FILE *f;
  if(!file) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no access log file specified"); 
    return;
  }
  logfile = apr_pstrdup(r->pool, file);
  qosc_unescaping(logfile);
  if(!apr_table_get(logt, logfile)) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, unknown log file");
    return;
  }
  f = fopen(logfile, "r");
  if(f) {
    FILE *d = fopen(settings->access_log, "w");
    if(d) {
#ifdef AP_REGEX_H
      ap_regex_t *regex = ap_pregcomp(r->pool, QOSC_REQ, AP_REG_EXTENDED);
#else
      regex_t *regex = ap_pregcomp(r->pool, QOSC_REQ, REG_EXTENDED);
#endif
      char line[QOSC_HUGE_STRING_LEN];
      while(!qosc_fgetline(line, sizeof(line), f)) {
        ap_regmatch_t ma;
        if(ap_regexec(regex, line, 1, &ma, 0) == 0) {
          char m[ma.rm_eo - ma.rm_so + 1];
          char *m_start;
          char *m_end;
          strncpy(m, &line[ma.rm_so], ma.rm_eo - ma.rm_so);
          m[ma.rm_eo - ma.rm_so] = '\0';
          m_start = strchr(m, ' ');
          while(m_start[0] == ' ') m_start++;
          m_end = strrchr(m, ' ');
          m_end[0] = '\0';
          fprintf(d, "%s\n", m_start);
          fflush(d);
        }
      }
      unlink(settings->status_file);
      fclose(d);
    } else {
      ap_rprintf(r, "Could not write log file.");
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOSC_LOG_PFX(0)"could not write log file '%s'", settings->access_log);
      fclose(f);
      return;
    }
    fclose(f);
  } else {
    ap_rprintf(r, "Could not read input.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"could not read input '%s'", logfile);
    return;
  }
  qosc_js_redirect(r, apr_pstrcat(r->pool, qosc_get_path(r), settings->server,
                                  ".do?action=qsfilter2", NULL));
}

/* qsfilter actions
   upload: get a file from the client
   import: get a file from local fs
   start: process the data
*/
static void qosc_qsfilter2(request_rec *r, qosc_settings_t *settings) {
  const char *action = apr_table_get(settings->qt, "action");
  if(action && (strcmp(action, "upload") == 0)) {
    qosc_qsfilter2_upload(r, settings);
  } else if(action && (strcmp(action, "import") == 0)) {
    qosc_qsfilter2_import(r, settings);
  } else if(action && (strcmp(action, "start") == 0)) {
    qosc_qsfilter2_start(r, settings);
  } else if(action && (strcmp(action, "report") == 0)) {
    qosc_qsfilter2_report(r, settings);
  } else if(action && (strcmp(action, "permit") == 0)) {
    qosc_qsfilter2_permitdeny(r, settings);
  } else if(action && (strcmp(action, "deny") == 0)) {
    qosc_qsfilter2_permitdeny(r, settings);
  } else if(action && (strcmp(action, "save+options") == 0)) {
    qosc_qsfilter2_saveoptions(r, settings);
  } else if(action && (strcmp(action, "edit") == 0)) {
    qosc_qsfilter2_edit(r, settings);
  } else if(action && (strcmp(action, "save") == 0)) {
    qosc_qsfilter2_edit(r, settings);
  } else if(action && (strcmp(action, "store") == 0)) {
    qosc_qsfilter2_store(r, settings);
  } else {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"unknown action");
  }
}

#define QOSC_ALERT_LINE_LEN 120
static char *qosc_crline(request_rec *r, const char *line) {
  char *string = "";
  const char *pos = line;
  while(pos && pos[0]) {
    string = apr_pstrcat(r->pool, string, apr_psprintf(r->pool, "%.*s", QOSC_ALERT_LINE_LEN, pos), "\\n", NULL);
    if(strlen(pos) > QOSC_ALERT_LINE_LEN) {
      pos = &pos[QOSC_ALERT_LINE_LEN];
    } else {
      pos = NULL;
    }
  }
  return string;
}

static int qosc_report_locations(request_rec *r, const char *server,
                                 int loc, const char *location_file, const char *file,
                                 apr_table_t *deny, apr_table_t *permit) {
  int open_lines = 0;
  FILE *f = fopen(file, "r");
  if(f) {
    char line[QOSC_HUGE_STRING_LEN];
    while(!qosc_fgetline(line, sizeof(line), f)) {
      if(strncmp(line, "# ADD line ", strlen("# ADD line ")) == 0) {
        char *url = &line[strlen("# ADD line ")];
        char *id = url;
        url = strstr(url, ": ");
        url[0] = '\0';
        url = url+2;
        if((apr_table_get(permit, url) == NULL) &&
           (apr_table_get(deny, url) == NULL)) {
          char *encoded = ap_escape_html(r->pool, url);
          char *crl = qosc_crline(r, encoded);
          open_lines++;
          ap_rputs("<tr class=\"row\">\n",r);
          ap_rprintf(r, "<td>&nbsp;%s:&nbsp;<a onclick=\"alert('%s')\" >%.*s %s</a></td>\n",
                     id,
                     crl, 60, encoded,
                     strlen(encoded) > 60 ? "..." : "");
          ap_rprintf(r, "<td>"
                     "<form action=\"%sqsfilter2.do\" method=\"get\">"
                     " <input name=\"action\" value=\"deny\" type=\"submit\">"
                     " <input name=\"action\" value=\"permit\" type=\"submit\">"
                     " <input name=\"server\" value=\"%s\"   type=\"hidden\">\n"
                     " <input name=\"loc\"    value=\"%d\"   type=\"hidden\">\n"
                     " <input name=\"url\"    value=\"%s\"   type=\"hidden\">\n"
                     "</form>"
                     "</td>\n",
                     qosc_get_path(r), server, loc, id);
          ap_rputs("</tr>\n",r);
        }
      }
    }
    fclose(f);
  } else {
    ap_rprintf(r, "failed to open '%s'", ap_escape_html(r->pool, file));
    return -1;
  }
  {
    struct stat attrib;
    if(stat(apr_pstrcat(r->pool, location_file, ".url_deny_new", NULL), &attrib) == 0) {
      ap_rputs("<tr class=\"row\"><td><i>updated black list: requires rule regeneration</i></td>"
               "<td></td></tr>\n",r);
    } else {
      if(open_lines == 0) {
        ap_rputs("<tr class=\"row\"><td>", r);
        ap_rprintf(r, "&nbsp;<form action=\"%sdownload.do\" method=\"get\">\n",
                   qosc_get_path(r));
        ap_rprintf(r, " <input name=\"server\" value=\"%s\" type=\"hidden\">\n",
                   ap_escape_html(r->pool, server));
        ap_rprintf(r, " <input name=\"loc\" value=\"%d\" type=\"hidden\">\n",
                   loc);
        ap_rprintf(r, " <input name=\"filter\" value=\"QS_PermitUri\" type=\"hidden\">\n"
                   " <input name=\"action\" value=\"get rules\" type=\"submit\">\n"
                   " </form>\n");

        ap_rprintf(r, "<form action=\"%sqsfilter2.do\" method=\"get\">\n",
                   qosc_get_path(r));
        ap_rprintf(r, " <input name=\"server\" value=\"%s\" type=\"hidden\">\n",
                   ap_escape_html(r->pool, server));
        ap_rprintf(r, " <input name=\"loc\" value=\"%d\" type=\"hidden\">\n",
                   loc);
        ap_rprintf(r, " <input title=\"edit the generated rules\""
                   " name=\"action\" value=\"edit\" type=\"submit\">\n"
                   " </form>\n");

        ap_rprintf(r, "<form action=\"%sqsfilter2.do\" method=\"get\">\n",
                   qosc_get_path(r));
        ap_rprintf(r, " <input name=\"server\" value=\"%s\" type=\"hidden\">\n",
                   ap_escape_html(r->pool, server));
        ap_rprintf(r, " <input name=\"loc\" value=\"%d\" type=\"hidden\">\n",
                   loc);
        ap_rprintf(r, " <input title=\"stores the rules to the httpd.conf files\""
                   " name=\"action\" value=\"store\" type=\"submit\">\n"
                   " </form>\n");

        ap_rputs("</td><td></td></tr>\n",r);
      }
    }
  }
  return open_lines;
}

static void qosc_server_qsfilter2(request_rec *r, qosc_settings_t *settings) {
  int inprogress = 0;
  int accessavailable = 0;
  char tmb[128];

  struct stat attrib;
  if(stat(settings->running_file, &attrib) == 0) {
    inprogress = 1;
  }
  ap_rputs("<table class=\"btable\"><tbody>\n",r);

  if(stat(settings->access_log, &attrib) == 0) {
    struct tm *ptr = localtime(&attrib.st_mtime);
    strftime(tmb, sizeof(tmb), "%H:%M:%S %d.%m.%Y", ptr);
    accessavailable = 1;
  }

  /* settings */
  if(!inprogress) {
    FILE *f = fopen(settings->server_options, "r");
    char *option = "";
    if(f) {
      char line[QOSC_HUGE_STRING_LEN];
      qosc_fgetline(line, sizeof(line), f);
      if(strlen(line) > 0) {
        option = apr_pstrdup(r->pool, line);
      }
      fclose(f);
    }
    ap_rputs("<tr class=\"rows\"><td>\n",r);
    ap_rputs("qsfilter2 options:<br>", r);
    ap_rprintf(r, "<form action=\"%sqsfilter2.do\" method=\"get\">\n",
               qosc_get_path(r));
    ap_rprintf(r, " <input name=\"server\" value=\"%s\"    type=\"hidden\">\n"
               "&nbsp;Query setting"
               " <select name=\"query\" >\n"
               "   <option %s>standard</option>\n"
               "   <option %s>multivalued (-m)</option>\n"
               "   <option %s>pcre only (-p)</option>\n"
               "   <option %s>single pcre (-s)</option>\n"
               " </select>\n"
               " <br>&nbsp;Disable path only regex (-h)"
               " <input type=\"checkbox\" name=\"path\" value=\"-h\" %s>\n"
               " <br><input name=\"action\" value=\"save options\" type=\"submit\">\n"
               " </form>\n",
               ap_escape_html(r->pool, settings->server),
               strlen(option) == 0 ? "selected" : "",
               strstr(option, "-m") != NULL ? "selected=\"selected\"" : "",
               strstr(option, "-p") != NULL ? "selected=\"selected\"" : "",
               strstr(option, "-s") != NULL ? "selected=\"selected\"" : "",
               strstr(option, "-h") != NULL ? "checked=\"checked\"" : "");
    ap_rputs("</td><td></td></tr>\n", r);
  }

  /* file upload/import */
  if(!inprogress) {
    ap_rputs("<tr class=\"rows\"><td>\n",r);
    ap_rputs("Upload access log data:<br>", r);
    ap_rprintf(r, "<form action=\"%sqsfilter2.do?server=%s&action=upload\""
               " method=\"post\" enctype=\"multipart/form-data\">\n",
               qosc_get_path(r), ap_escape_html(r->pool, settings->server));
    ap_rprintf(r, " <input name=\"access_log\" value=\"\" type=\"file\" size=\"50\">\n"
               " <input name=\"action\" value=\"upload\" type=\"submit\">\n"
               " </form>\n", ap_escape_html(r->pool, settings->server));
    ap_rputs("</td><td></td></tr>\n", r);

    {
      apr_table_t *logt = qosc_read_logfile(r, settings->server_conf);
      if(apr_table_elts(logt)->nelts > 0) {
        apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(logt)->elts;
        int i;
        ap_rputs("<tr class=\"rows\"><td>\n",r);
        ap_rputs("Import access log data:<br>", r);
        for(i = 0; i < apr_table_elts(logt)->nelts; i++) {
          ap_rprintf(r, "&nbsp;<form action=\"%sqsfilter2.do\" method=\"get\">\n",
                     qosc_get_path(r));
          ap_rprintf(r, "%s"
                     " <input name=\"file\" value=\"%s\"    type=\"hidden\">\n"
                     " <input name=\"server\" value=\"%s\"    type=\"hidden\">\n"
                     " <input name=\"action\" value=\"import\" type=\"submit\">\n"
                     " </form><br>\n",
                     ap_escape_html(r->pool, entry[i].key),
                     ap_escape_html(r->pool, entry[i].key),
                     ap_escape_html(r->pool, settings->server));
        }
        
        ap_rputs("</td><td></td></tr>\n", r);
      }
    }
  }

  /* start analysis */
  ap_rputs("<tr class=\"rows\"><td>\n",r);
  if(!inprogress) {
    if(accessavailable) {
      ap_rprintf(r, "Access log data loaded (%s, %d bytes).<br>", tmb, attrib.st_size);
      ap_rprintf(r, "<form action=\"%sqsfilter2.do\" method=\"get\">\n",
                 qosc_get_path(r));
      ap_rputs("&nbsp;Generate rules:", r);
      ap_rprintf(r, " <input name=\"server\" value=\"%s\"    type=\"hidden\">\n"
                 " <input name=\"action\" value=\"start\" type=\"submit\">\n"
                 " </form>\n", ap_escape_html(r->pool, settings->server));
    } else {
      ap_rputs("<br>No access log data available.<br><br>", r);
    }
  } else {
    FILE *fr = fopen(settings->running_file, "r");
    ap_rputs("<br><b>Rule generation process is running.</b><br><br>Status:<ul>\n", r);
    if(fr) {
      char line[QOSC_HUGE_STRING_LEN];
      while(!qosc_fgetline(line, sizeof(line), fr)) {
        ap_rprintf(r, "%s\n", line);
      }
      fclose(fr);
    }
    ap_rputs("</ul><br>\n", r);
  }
  ap_rputs("</td><td></td></tr>\n", r);

  /* results */
  if(!inprogress) {
    FILE *fs = fopen(settings->status_file, "r");
    if(fs) {
      int i = 0;
      char line[QOSC_HUGE_STRING_LEN];
      while(!qosc_fgetline(line, sizeof(line), fs)) {
        if(i == 0) {
          ap_rputs("<tr class=\"rowe\"><td>\n",r);
          ap_rprintf(r, "Results (%s):<br>&nbsp;<i>Note: please confirm all requests"
                     " (deny/permit) and then"
                     " repeat the rule generation if necessary.</i>\n", line);
          ap_rputs("</td><td></td></tr>\n", r);
        } else {
          char *id = line;
          char *st = strchr(line, ' ');
          if(st) {
            char *loc;
            st[0] = '\0';
            st++;
            loc = strchr(st, ' ');
            loc[0] = '\0';
            loc++;
            ap_rputs("<tr class=\"rows\"><td>\n",r);
            //ap_rprintf(r, "<a name=\"%d\" href=\"%sqsfilter2.do?server=%s&action=report&loc=%d\">",
            ap_rprintf(r, "<a name=\"%d\" title=\"stdout (raw qsfilter2 data)\" "
                       "href=\"%sdownload.do?server=%s&loc=%d&type=rep\">",
                       i, qosc_get_path(r), ap_escape_html(r->pool, settings->server), i);
            if(strcmp(loc, "404") == 0) {
              ap_rprintf(r, "others (404)<a> ");
            } else {
              ap_rprintf(r, "%s<a> ", loc);
            }
            if(strcmp(st, "0") != 0) {
              ap_rprintf(r, "<b>command failed</b> ");
            }
            if(stat(apr_pstrcat(r->pool, id, ".err", NULL), &attrib) == 0) {
              if(attrib.st_size > 0) {
                ap_rprintf(r, "<a title=\"stderr\" "
                           "href=\"%sdownload.do?server=%s&loc=%d&type=err\">(stderr)</a> ",
                           qosc_get_path(r), ap_escape_html(r->pool, settings->server), i);
              }
            }
            ap_rputs("</td><td></td></tr>\n", r);
            {
              apr_table_t *permit = qosc_file2table(r->pool, apr_pstrcat(r->pool, id, ".url_permit", NULL));
              apr_table_t *deny = qosc_file2table(r->pool, apr_pstrcat(r->pool, id, ".url_deny", NULL));
              qosc_report_locations(r, settings->server, i, id,
                                    apr_pstrcat(r->pool, id, ".rep", NULL), deny, permit);
            }
          }
        }
        i++;
      }
      fclose(fs);
    }
  }
  ap_rputs("</tbody></table>\n", r);
}

/* server main window */
static void qosc_server(request_rec *r, qosc_settings_t *settings) {
  DIR *dir;
  const char *location = apr_table_get(settings->qt, "loc");
  const char *action = apr_table_get(settings->qt, "action");
  dir = opendir(settings->server_dir);
  if(dir == NULL) {
    ap_rputs("Could not open server directory.", r);
    return;
  }
  closedir(dir);
  if(action && (strcmp(action, "load") == 0)) {
    qosc_server_load(r, settings);
  } else if(action && (strcmp(action, "qsfilter2") == 0)) {
    qosc_server_qsfilter2(r, settings);
  } else {
    FILE *f = fopen(settings->server_conf, "r");
    if(f) {
      int hosts = 0;
      int locations = 0;
      char *conf = NULL;
      char line[QOSC_HUGE_STRING_LEN];
      char *local_file = apr_pstrcat(r->pool, settings->server_dir, "/httpd.conf", NULL);
      while(!qosc_fgetline(line, sizeof(line), f)) {
        if(strncmp(line, "conf=", strlen("conf=")) == 0) {
          conf = apr_pstrdup(r->pool, &line[strlen("conf=")]);
        }
        if(strncmp(line, "host=", strlen("host=")) == 0) {
          hosts++;
        }
        if(strncmp(line, "location=", strlen("location=")) == 0) {
          locations++;
        }
      }
      fclose(f);
      ap_rputs("<table class=\"btable\"><tbody>\n",r);
      ap_rputs("<tr class=\"rows\"><td>\n",r);
      ap_rprintf(r, "Server configuration %s"
                 "<br>&nbsp;VirtualHosts: %d"
                 "<br>&nbsp;Locations: %d<br><br>",
                 conf == NULL ? "-" : conf,
                 hosts, locations);
      ap_rputs("</td></tr>\n",r);

      f = fopen(local_file, "r");
      if(f) {
        fclose(f);
        ap_rputs("<tr class=\"rows\"><td>\n",r);
        ap_rputs("Update the httpd.conf file:<br>", r);
        ap_rprintf(r, "<form action=\"%sct.do?server=%s&action=set\""
                   " method=\"post\" enctype=\"multipart/form-data\">\n",
                   qosc_get_path(r), ap_escape_html(r->pool, settings->server));
        ap_rprintf(r, "&nbsp;<input name=\"httpd_conf\" value=\"\" type=\"file\" size=\"50\">\n"
                   " <input name=\"action\" value=\"upload\" type=\"submit\">\n"
                   " </form>\n", ap_escape_html(r->pool, settings->server));
        ap_rputs("</td></tr>\n",r);
        ap_rputs("</tbody></table>\n",r);
      }
    }
  }
}

static void qosc_body(request_rec *r, qosc_settings_t *settings) {
  if(strstr(r->parsed_uri.path, "/ct.do") != NULL) {
    qosc_create_server(r, settings);
    return;
  }
  if(strstr(r->parsed_uri.path, "/qsfilter2.do") != NULL) {
    qosc_qsfilter2(r, settings);
    return;
  }
  if(!settings->sconf->qsfilter2) {
    ap_rputs("No qsfilter2 executable defined.", r);
  }
  qosc_server(r, settings);
}

static void qosc_server_list(request_rec *r, qosc_settings_t *settings) {
  qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  DIR *dir = opendir(sconf->path);
  if(dir) {
    struct dirent *de;
    while((de = readdir(dir)) != 0) {
      if(de->d_name[0] != '.') {
        char *h = apr_psprintf(r->pool, "/%s.do", de->d_name);
        if(settings && (strcmp(settings->server, de->d_name) == 0)) {
          ap_rprintf(r, "<tr class=\"rowts\"><td>"
                     "<a href=\"%s%s.do\">%s</a></td></tr>\n",
                     qosc_get_path(r), ap_escape_html(r->pool, de->d_name),
                     ap_escape_html(r->pool, de->d_name));
          ap_rprintf(r, "<tr class=\"row\"><td>"
                     "&nbsp;<a href=\"%s%s.do?action=qsfilter2\" "
                     "title=\"creates request line white list rules\">"
                     "qsfilter2</a></td></tr>\n",
                     qosc_get_path(r), ap_escape_html(r->pool, de->d_name));
          ap_rprintf(r, "<tr class=\"row\"><td>"
                     "&nbsp;<a href=\"%s%s.do?action=load\" "
                     "title=\"reloads the server configuration from the specified file\" >"
                     "reload configuration"
                     "</a></td></tr>\n",
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

static int qosc_download(request_rec * r) {
  qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(r->server->module_config,
                                                                  &qos_control_module);
  apr_table_t *qt = qosc_get_query_table(r);
  const char *server = qosc_get_server(qt);
  const char *loc = apr_table_get(qt, "loc");
  const char *filter = apr_table_get(qt, "filter");
  const char *type = apr_table_get(qt, "type");
  char *file_name = NULL;
  char *server_dir = server_dir = apr_pstrcat(r->pool, sconf->path, "/", server, NULL);
  ap_set_content_type(r, "text/plain");
  if(!server) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no server");
    return OK;
  }
  if(!loc) {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, no location file");
    return;
  }
  file_name = qosc_locfile_id2name(r, atoi(loc), 1);
  if(file_name && file_name[0]) {
    if(type && (strcmp(type, "err") == 0)) {
      file_name = apr_pstrcat(r->pool, file_name, ".err", NULL);
    } else if(type && (strcmp(type, "rep") == 0)) {
      file_name = apr_pstrcat(r->pool, file_name, ".rep", NULL);
    } else {
      /* default */
      struct stat attrib;
      char *dedicated_rules = apr_pstrcat(r->pool, file_name, ".rules", NULL);
      if(stat(dedicated_rules, &attrib) == 0) {
        file_name = apr_pstrcat(r->pool, file_name, ".rules", NULL);
        //filter = NULL;
      } else {
        file_name = apr_pstrcat(r->pool, file_name, ".rep", NULL);
      }
    }
  }
  if(file_name && file_name[0]) {
    FILE *f = fopen(file_name, "r");
    if(f) {
      char line[QOSC_HUGE_STRING_LEN];
      while(!qosc_fgetline(line, sizeof(line), f)) {
        if(filter) {
          if(strncmp(line, filter, strlen(filter)) == 0) {
            ap_rprintf(r, "%s\n", line);
          }
        } else {
          ap_rprintf(r, "%s\n", line);
        }
      }      
      fclose(f);
    } else {
      ap_rprintf(r, "Invalid request.");
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOSC_LOG_PFX(0)"invalid request, could not open %s", file_name);
      return;
    }
  } else {
    ap_rprintf(r, "Invalid request.");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOSC_LOG_PFX(0)"invalid request, could not determine file name");
    return;
  }
  return OK;
}

/************************************************************************
 * "public"
 ***********************************************************************/

/************************************************************************
 * handlers
 ***********************************************************************/

static int qosc_favicon(request_rec *r) {
  int i;
  unsigned const char ico[] = { 0x0,0x0,0x1,0x0,0x1,0x0,0x10,0x10,0x0,0x0,0x1,0x0,0x20,0x0,0x68,0x4,0x0,0x0,0x16,0x0,0x0,0x0,0x28,0x0,0x0,0x0,0x10,0x0,0x0,0x0,0x20,0x0,0x0,0x0,0x1,0x0,0x20,0x0,0x0,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xfa,0xfa,0xfb,0xfd,0xb1,0xb1,0xe9,0xfd,0x6a,0x6a,0xea,0xfd,0x47,0x47,0xea,0xfd,0x47,0x47,0xe9,0xfd,0x6a,0x6b,0xea,0xfd,0xb2,0xb2,0xea,0xfd,0xfb,0xfb,0xfb,0xfd,0xfe,0xfe,0xfe,0xfd,0xe9,0xe8,0xf9,0xfd,0xa0,0xb8,0xdc,0xfd,0xc0,0xdf,0xe8,0xfd,0xff,0xff,0xff,0xfd,0xfc,0xfc,0xfc,0xfd,0xf9,0xf9,0xf9,0xfd,0xc1,0xc1,0xee,0xfd,0x27,0x27,0xec,0xfd,0x0,0x0,0xfe,0xfd,0x0,0x0,0xfe,0xfd,0x0,0x0,0xf1,0xfd,0x0,0x0,0xf1,0xfd,0x0,0x0,0xfe,0xfd,0x0,0x0,0xfe,0xfd,0x2f,0x2c,0xe6,0xfd,0x7c,0x60,0xc1,0xfd,0x3e,0x10,0x8c,0xfd,0x95,0x9f,0xd6,0xfd,0xfc,0xfd,0xfe,0xfd,0xff,0xff,0xff,0xfd,0xfe,0xfe,0xfe,0xfd,0x68,0x6c,0xac,0xfd,0x6,0x6,0xbb,0xfd,0x0,0x0,0xf1,0xfd,0x0,0x0,0x7d,0xfd,0x22,0x22,0x43,0xfd,0x52,0x52,0x53,0xfd,0x52,0x52,0x53,0xfd,0x21,0x22,0x45,0xfd,0x1a,0xe,0xbb,0xfd,0x36,0x7,0x8c,0xfd,0x30,0x4,0x91,0xfd,0x56,0x54,0x96,0xfd,0xfe,0xfe,0xfe,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xcd,0xda,0xf0,0xfd,0x7,0x5a,0xf2,0xfd,0x0,0x4,0x8b,0xfd,0x1,0x1,0x18,0xfd,0x9e,0x9e,0x9e,0xfd,0xdb,0xdb,0xdb,0xfd,0xa0,0xa0,0xa0,0xfd,0xa1,0xa1,0xa1,0xfd,0x72,0x5b,0xac,0xfd,0x3c,0x6,0x67,0xfd,0x19,0x2,0xc9,0xfd,0x0,0xb,0x6a,0xfd,0x9,0xda,0xda,0xfd,0xd0,0xf0,0xf0,0xfd,0xff,0xff,0xff,0xfd,0xfe,0xfe,0xfe,0xfd,0x3c,0x80,0xea,0xfd,0x0,0x62,0xf7,0xfd,0x3,0x11,0x9d,0xfd,0x0,0x0,0x87,0xfd,0xe,0xe,0xe,0xfd,0x3,0x1d,0x2d,0xfd,0x0,0x77,0xc2,0xfd,0x0,0x76,0xc2,0xfd,0x0,0x19,0x89,0xfd,0x5,0x0,0xed,0xfd,0x0,0x0,0x64,0xfd,0x4,0x28,0x28,0xfd,0x0,0xf8,0xf8,0xfd,0x3f,0xea,0xea,0xfd,0xfe,0xfe,0xfe,0xfd,0xcf,0xda,0xec,0xfd,0x0,0x64,0xfc,0xfd,0x0,0x3a,0x92,0xfd,0x9b,0x9a,0xa1,0xfd,0x1a,0x19,0xf3,0xfd,0x0,0x0,0x82,0xfd,0x0,0x0,0x0,0xfd,0x0,0x1e,0x49,0xfd,0x0,0x1d,0xcc,0xfd,0x0,0x0,0xfd,0xfd,0x0,0x0,0x69,0xfd,0x1c,0x1c,0x1c,0xfd,0x99,0x99,0x98,0xfd,0x0,0x94,0x95,0xfd,0x0,0xfb,0xfb,0xfd,0xd2,0xed,0xed,0xfd,0x8c,0xb1,0xea,0xfd,0x0,0x65,0xff,0xfd,0x10,0x28,0x49,0xfd,0xe4,0xe4,0xe4,0xfd,0x7,0x22,0x7f,0xfd,0x0,0x0,0xfe,0xfd,0x0,0x0,0xb6,0xfd,0x0,0x0,0xfc,0xfd,0x0,0x0,0xfc,0xfd,0x0,0x0,0xaa,0xfd,0x0,0x0,0x0,0xfd,0x8,0x23,0x34,0xfd,0xe6,0xe6,0xe6,0xfd,0xe,0x49,0x4a,0xfd,0x0,0xff,0xff,0xfd,0x90,0xea,0xea,0xfd,0x6a,0x9c,0xea,0xfd,0x0,0x65,0xfe,0xfd,0x3b,0x41,0x4a,0xfd,0xb5,0xb5,0xb5,0xfd,0x0,0x6d,0xb4,0xfd,0x0,0x23,0xe0,0xfd,0x0,0x0,0xd6,0xfd,0x0,0x0,0xa6,0xfd,0x0,0x0,0xbf,0xfd,0x0,0x0,0xd5,0xfd,0x0,0x25,0x58,0xfd,0x0,0x6b,0xb1,0xfd,0xb8,0xb8,0xb8,0xfd,0x38,0x49,0x4a,0xfd,0x0,0xfe,0xfe,0xfd,0x6e,0xe9,0xe9,0xfd,0x6a,0x9c,0xea,0xfd,0x0,0x65,0xfe,0xfd,0x3c,0x42,0x4b,0xfd,0xb5,0xb5,0xb5,0xfd,0x0,0x6e,0xb5,0xfd,0x0,0x24,0x5a,0xfd,0x0,0x0,0xb9,0xfd,0x0,0x0,0x9f,0xfd,0x0,0x0,0x9f,0xfd,0x0,0x0,0xc9,0xfd,0x0,0x26,0xe0,0xfd,0x0,0x6b,0xb1,0xfd,0xb8,0xb8,0xb8,0xfd,0x39,0x49,0x4a,0xfd,0x0,0xfe,0xfe,0xfd,0x6d,0xe9,0xe9,0xfd,0x8a,0xaf,0xea,0xfd,0x0,0x65,0xff,0xfd,0x12,0x28,0x49,0xfd,0xe5,0xe5,0xe5,0xfd,0x7,0x23,0x34,0xfd,0x0,0x0,0x0,0xfd,0x0,0x0,0xad,0xfd,0x0,0x0,0xfc,0xfd,0x0,0x0,0xfc,0xfd,0x0,0x0,0xb8,0xfd,0x0,0x0,0xfe,0xfd,0x8,0x24,0x7d,0xfd,0xe7,0xe7,0xe7,0xfd,0x10,0x49,0x49,0xfd,0x0,0xff,0xff,0xfd,0x8e,0xea,0xea,0xfd,0xcc,0xd8,0xec,0xfd,0x0,0x64,0xfd,0xfd,0x0,0x38,0x8d,0xfd,0xa0,0xa0,0xa0,0xfd,0x1a,0x1a,0x1a,0xfd,0x0,0x0,0x6c,0xfd,0x0,0x0,0xfd,0xfd,0x0,0x1c,0xca,0xfd,0x0,0x1b,0x46,0xfd,0x0,0x0,0x0,0xfd,0x0,0x0,0x87,0xfd,0x1c,0x1c,0xf2,0xfd,0x9e,0x9e,0xa3,0xfd,0x0,0x8f,0x90,0xfd,0x0,0xfc,0xfc,0xfd,0xd0,0xec,0xec,0xfd,0xfe,0xfe,0xfe,0xfd,0x37,0x7d,0xeb,0xfd,0x0,0x61,0xf5,0xfd,0x4,0x11,0x24,0xfd,0x0,0x0,0x66,0xfd,0xd,0xd,0xf5,0xfd,0x2,0x1d,0x8e,0xfd,0x0,0x78,0xc5,0xfd,0x0,0x77,0xc3,0xfd,0x3,0x1c,0x2b,0xfd,0xd,0xd,0xd,0xfd,0x0,0x0,0x8d,0xfd,0x5,0x26,0x98,0xfd,0x0,0xf6,0xf6,0xfd,0x3a,0xea,0xea,0xfd,0xfe,0xfe,0xfe,0xfd,0xff,0xff,0xff,0xfd,0xc8,0xd7,0xef,0xfd,0x6,0x5a,0xda,0xfd,0x0,0x4,0x6b,0xfd,0x2,0x2,0xa4,0xfd,0xa6,0xa6,0xb8,0xfd,0xda,0xda,0xda,0xfd,0x9d,0x9e,0x9d,0xfd,0x9e,0x9e,0x9e,0xfd,0xdb,0xdb,0xdb,0xfd,0xa4,0xa4,0xa3,0xfd,0x2,0x2,0xe,0xfd,0x0,0xb,0x8f,0xfd,0x6,0xdb,0xf3,0xfd,0xcb,0xef,0xf0,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xfe,0xfe,0xfe,0xfd,0x65,0x6a,0xa1,0xfd,0x4,0x4,0xa6,0xfd,0x0,0x0,0x8f,0xfd,0x0,0x0,0x47,0xfd,0x2a,0x2a,0x39,0xfd,0x5b,0x5b,0x5b,0xfd,0x5b,0x5b,0x5b,0xfd,0x29,0x29,0x39,0xfd,0x0,0x0,0x47,0xfd,0x0,0x0,0x90,0xfd,0x4,0x4,0x72,0xfd,0x68,0x74,0xad,0xfd,0xfe,0xfe,0xfe,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xfc,0xfc,0xfc,0xfd,0xf8,0xf8,0xfa,0xfd,0xb9,0xb8,0xd8,0xfd,0x20,0x20,0x9c,0xfd,0x0,0x0,0x99,0xfd,0x0,0x0,0x98,0xfd,0x0,0x0,0x8c,0xfd,0x0,0x0,0x8d,0xfd,0x0,0x0,0x98,0xfd,0x0,0x0,0x99,0xfd,0x21,0x21,0x9c,0xfd,0xbb,0xbb,0xd9,0xfd,0xf8,0xf8,0xf8,0xfd,0xfc,0xfc,0xfc,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xf8,0xf7,0xf9,0xfd,0xa7,0xa7,0xcf,0xfd,0x60,0x60,0xb2,0xfd,0x3e,0x3e,0xa6,0xfd,0x3e,0x3e,0xa6,0xfd,0x60,0x60,0xb3,0xfd,0xa8,0xa8,0xcf,0xfd,0xf8,0xf8,0xf9,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xfd,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0 };
  ap_set_content_type(r, "image/x-icon");
  for(i=0; i < sizeof(ico); i++) {
    ap_rputc(ico[i], r);
  }
  return OK;
}

static void qosc_js(request_rec *r) {
  ap_rputs("<!--\n\
function checkserver ( form ) {\n\
  if(form.server.value == \"ct\") {\n\
    alert(\"Sorry, this is a reserved word. Please choose another server name.\" );\n\
    return false;\n\
  }\n\
  if(form.server.value == \"download\") {\n\
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
      if(form.server.value.charAt(i) != \"_\") {\n\
        chkZ = -1;\n\
      }\n\
  }\n\
  if (chkZ == -1) {\n\
    alert(\"Allowed character set for server name: 0-9, a-z and '_'.\" );\n\
    return false;\n\
  }\n\
  return true;\n\
}\n\
//-->\n", r);
}



static int qosc_handler(request_rec * r) {
  if (strcmp(r->handler, "qos-control") != 0) {
    return DECLINED;
  } else  if(strstr(r->parsed_uri.path, "/favicon.ico") != NULL) {
    return qosc_favicon(r);
  } else if(strstr(r->parsed_uri.path, "/download.do") != NULL) {
    return qosc_download(r);
  } else {
    qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(r->server->module_config,
                                                                        &qos_control_module);
    qosc_settings_t *settings = qosc_get_settings(r);
    apr_table_t *qt = qosc_get_query_table(r);
    const char *action = apr_table_get(qt, "action");
    ap_set_content_type(r, "text/html");
    apr_table_set(r->headers_out,"Cache-Control","no-cache");
    if(!r->header_only) {
      ap_rputs("<html><head><title>mod_qos control</title>\n", r);
      ap_rprintf(r,"<link rel=\"shortcut icon\" href=\"%s/favicon.ico\"/>\n",
                 ap_escape_html(r->pool, r->parsed_uri.path));
      ap_rputs("<meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n", r);
      ap_rputs("<meta name=\"author\" content=\"Pascal Buchbinder\">\n", r);
      ap_rputs("<meta http-equiv=\"Pragma\" content=\"no-cache\">\n", r);
      if(settings && action && (strcmp(action, "qsfilter2") == 0)) {
        struct stat attrib;
        if(stat(settings->running_file, &attrib) == 0) {
          ap_rprintf(r, "<meta http-equiv=\"refresh\" content=\"5; URL=%s?%s\">",
                     r->parsed_uri.path, r->parsed_uri.query == NULL ? "" : r->parsed_uri.query);
        }
      }
      ap_rputs("<style TYPE=\"text/css\">\n", r);
      ap_rputs("<!--", r);
      qosc_css(r);
      ap_rputs("-->\n", r);
      ap_rputs("</style>\n", r);
      ap_rputs("<script language=\"JavaScript\" type=\"text/javascript\">\n", r);
      qosc_js(r);
      ap_rputs("</script>\n", r);
      ap_rputs("</head><body>", r);

      ap_rputs("<h2>mod_qos control</h2>\n\
<table class=\"btable\">\n\
  <tbody>\n\
    <tr class=\"row\">\n\
      <td style=\"width: 230px;\" >\n\
      <table class=\"btable\">\n\
        <tbody>\n", r);
      qosc_server_list(r, settings);
      ap_rputs("          <tr class=\"row\">\n\
            <td>&nbsp;</rd></tr>\n", r);
      ap_rputs("          <tr class=\"rowe\">\n\
            <td>\n", r);
      ap_rprintf(r, "<form action=\"%sct.do\" method=\"get\" onsubmit=\"return checkserver(this);\">\n",
                 qosc_get_path(r));
      ap_rputs("Add a new server:\n\
              <input name=\"server\" value=\"\"    type=\"text\">\n\
              <input name=\"action\" value=\"add\" type=\"submit\">\n\
            </form>\n\
            </td>\n\
          </tr>\n",r);
      if(sconf->viewer) {
        ap_rprintf(r, "<tr class=\"rowe\">\n"
                   "<td><a href=\"%s?option=ip\">mod_qos viewer</a></td>\n"
                   "</tr>\n", sconf->viewer);
      }
      ap_rputs("        </tbody>\n\
      </table>\n\
      </td>\n\
      <td >\n", r);
      /* TEXT */
      if(settings) {
        qosc_body(r, settings);
      } else {
        ap_rputs("Please choose or create a server.", r);
      }
      ap_rputs("      </td>\n\
    </tr>\n\
  </tbody>\n\
</table>\n", r);
      ap_rputs("</body></html>", r);
    }
  }
  return OK;
}

static void qosc_search_viewer(ap_directive_t * node, server_rec *bs) {
  ap_directive_t *pdir;
  for(pdir = node; pdir != NULL; pdir = pdir->next) {
    if(strcasecmp(pdir->directive, "SetHandler") == 0) {
      if(strcmp(pdir->args, "qos-viewer") == 0) {
        if(pdir->parent->args) {
          qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(bs->module_config,
                                                                          &qos_control_module);
          char *c;
          sconf->viewer = apr_pstrdup(sconf->pool, pdir->parent->args);
          c = sconf->viewer;
          while(c[0] && (c[0] != ' ') && (c[0] != '\t') && (c[0] != '>')) c++;
          c[0] = '\0';
        }
      }
    }
    if(pdir->first_child != NULL) {
      qosc_search_viewer(pdir->first_child, bs);
    }
  }
}
          
static int qosc_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *bs) {
  char *rev = qosc_revision(ptemp);
  char *vs = apr_psprintf(pconf, "mod_qos_control/%s", rev);
  ap_add_version_component(pconf, vs);
  qosc_search_viewer(ap_conftree, bs);
  return DECLINED;
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
  qosc_srv_config_t *sconf = apr_pcalloc(p, sizeof(qosc_srv_config_t));
  sconf->pool = p;
  sconf->path = apr_pstrdup(p, "/var/tmp/qos_control");
  sconf->qsfilter2 = NULL;
  sconf->viewer = NULL;
  return sconf;
}

static void *qosc_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  return basev;
}

const char *qosc_wd_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(cmd->server->module_config,
                                                                  &qos_control_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if((strlen(path) < 0) || (path[0] != '/')) {
    return apr_psprintf(cmd->pool, "%s: invalid path", 
                        cmd->directive->directive);
  }
  sconf->path = apr_pstrdup(cmd->pool, path);
  return NULL;
}

const char *qosc_filter2_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  qosc_srv_config_t *sconf = (qosc_srv_config_t*)ap_get_module_config(cmd->server->module_config,
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
  ap_hook_post_config(qosc_post_config, pre, NULL, APR_HOOK_MIDDLE);
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
