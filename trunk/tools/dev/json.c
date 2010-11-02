/**
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2010 Pascal Buchbinder
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

static const char revision[] = "$Id: json.c,v 1.2 2010-11-02 19:26:28 pbuchbinder Exp $";

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* apr */
#include <apr.h>
#include <apr_uri.h>
#include <apr_signal.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_support.h>
#include <apr_base64.h>

#define HTTP_BAD_REQUEST                   400
#define QOS_J_ERROR "HTTP_BAD_REQUEST QOS JSON PARSER: FORMAT ERROR"

const char data00[] = " \"mein name (\\\"oder was\\\")\"";
const char data01[] = " { \"name\" : \"value\" , \"und noch\" : \"mehr text\" }";
const char data10[] = " {\n" \
"    \"name\": \"Jack (\\\"Bee\\\") Nimble\", \n" \
"    \"format\": {\n" \
"        \"type\":       \"rect\",\n" \
"        \"width\":      1920, \n" \
"        \"height\":     1080,\n" \
"        \"interlace\":  false, \n" \
"        \"frame rate\": 24\n" \
"    }\n" \
"}\n" \
"";
const char data11[] = "[\"Label 0\",{\"type\":\"Text\",\"label\":\"text label 1\",\"title\":\"this is the tooltip for text label 1\",\"editable\":true},{\"type\":\"Text\",\"label\":\"branch 1\",\"title\":\"there should be children here\",\"expanded\":true,\"children\":[\"Label 1-0\"]},{\"type\":\"Text\",\"label\":\"text label 2\",\"title\":\"this should be an href\",\"href\":\"http://www.yahoo.com\",\"target\":\"something\"},{\"type\":\"HTML\",\"html\":\"<a href=\\\"developer.yahoo.com/yui\\\">YUI</a>\",\"hasIcon\":false},{\"type\":\"MenuNode\",\"label\":\"branch 3\",\"title\":\"this is a menu node\",\"expanded\":false,\"children\":[\"Label 3-0\",\"Label 3-1\"]}]";

static int j_val(apr_pool_t *pool, char **val, apr_table_t *tl, char *name);

static char *j_escape_url(apr_pool_t *pool, const char *c) {
  char buf[4];
  char special[] = " \t()<>@,;:\\/[]?={}\"'&%+";
  char *r = apr_pcalloc(pool, 3 * strlen(c));
  const char *p = c;
  int i = 0;
  while(p && p[0]) {
    char c = p[0];
    if(!apr_isprint(c) || strchr(special, c)) {
      sprintf(buf, "%02x", p[0]);
      r[i] = '%'; i++;
      r[i] = buf[0]; i++;
      r[i] = buf[1]; i++;
    } else {
      r[i] = c;
      i++;
    }
    p++;
  }
  return r;
}

static char *j_strchr(char *data, char d) {
  char *q = data;
  if(!q) {
    return NULL;
  }
  if(q[0] == d) {
    return q;
  }
  while(q[0]) {
    if((q[0] == d) && (q[-1] != '\\')) {
      return q;
    }
    q++;
  }
  return NULL;
}

static char *j_skip(char *in) {
  if(!in) return NULL;
  while(in[0] && (in[0] <= ' ')) {
    in++;
  }
  return in;
}

static int j_string(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, char **n) {
  char *d = *val;
  char *v = d;
  char *end = j_strchr(d, '"');
  if(!end) {
    apr_table_add(tl, QOS_J_ERROR, "error while parsing string (no ending double quote)");
    return HTTP_BAD_REQUEST;
  }
  end[0] = '\0';
  end++;
  *val = j_skip(end);
  /* TODO, improve string format validation */
  while(v[0]) {
    if(v[0] < ' ') {
      apr_table_add(tl, QOS_J_ERROR, "error while parsing string (invalid character)");
      return HTTP_BAD_REQUEST;
    }
    v++;
  }
  *n = d;
  return APR_SUCCESS;
}

static int j_num(apr_pool_t *pool, char **val, apr_table_t *tl, char *name) {
  return APR_SUCCESS;
}

static int j_obj(apr_pool_t *pool, char **val, apr_table_t *tl, char *name) {
  char *d = j_skip(*val);
  int rc;
  while(d && d[0]) {
    if(*d != '\"') {
      apr_table_add(tl, QOS_J_ERROR, "error while parsing object (missing string)");
      return HTTP_BAD_REQUEST;
    } else {
      /* list of string ":" value pairs (sepated by ',') */
      char *v = NULL;
      char *thisname;
      d++;
      rc = j_string(pool, &d, tl, name, &v);
      if(rc != APR_SUCCESS) {
	return rc;
      }
      thisname = apr_pstrcat(pool, name, "." , v, NULL);
      d = j_strchr(d, ':');
      if(!d) {
	apr_table_add(tl, QOS_J_ERROR, "error while parsing object (missing value)");
	return HTTP_BAD_REQUEST;
      }
      d++;
      rc = j_val(pool, &d, tl, thisname);
      if(rc != APR_SUCCESS) {
	return rc;
      }
      d = j_skip(d);
      if(!d) {
	apr_table_add(tl, QOS_J_ERROR, "error while parsing object (unexpected end)");
	return HTTP_BAD_REQUEST;
      }
      if(d[0] == '}') {
	d++;
	*val = d;
	return APR_SUCCESS;
      } else if(d[0] == ',') {
	d = j_strchr(d, '"');
      } else {
	apr_table_add(tl, QOS_J_ERROR, "error while parsing object (unexpected end/wrong delimiter)");
	return HTTP_BAD_REQUEST;
      }
    }
    //  apr_table_add(tl, name, j_escape_url(pool, v));
  }
  return APR_SUCCESS;
}

static int j_ar(apr_pool_t *pool, char **val, apr_table_t *tl, char *name) {
  return APR_SUCCESS;
}

static int j_val(apr_pool_t *pool, char **val, apr_table_t *tl, char *name) {
  char *d = j_skip(*val);
  int rc;
  /* either object, array, string, number, "true", "false", or "null" */
  if(d[0] == '{') {
    d++;
    rc = j_obj(pool, &d, tl, apr_pstrcat(pool, name, ".o", NULL));
  } else if(d[0] == '[') {
    d++;
    rc = j_ar(pool, &d, tl, apr_pstrcat(pool, name, ".a", NULL));
  } else if(strncmp(d,"null",4) == 0) {
    d+=4;
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), ".v", NULL), "null");
  } else if(strncmp(d,"true",4) == 0) {
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), ".v", NULL), "true");
    d+=4;
  } else if(strncmp(d,"false",5) == 0) {
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), ".v", NULL), "false");
    d+=5;
  } else if(*d == '-' || (*d >= '0' && *d <= '9')) {
    rc = j_num(pool, &d, tl, apr_pstrcat(pool, name, ".v", NULL));
  } else if(*d == '\"') {
    char *n = apr_pstrcat(pool, name, ".v", NULL);
    char *v = NULL;
    d++;
    rc = j_string(pool, &d, tl, n, &v);
    apr_table_addn(tl, j_escape_url(pool, n), j_escape_url(pool, v));
  } else {
    /* error */
    apr_table_add(tl, QOS_J_ERROR, "error while parsing value (invalid type)");
    return HTTP_BAD_REQUEST;
  }
  if(rc != APR_SUCCESS) {
    return rc;
  }
  *val = d;
  return APR_SUCCESS;
}

void process(apr_pool_t *pool, const char *msg) {
  int rc;
  apr_table_entry_t *entry;
  int i;
  char *p;
  apr_table_t *tl = apr_table_make(pool, 200);
  p = apr_pstrdup(pool, msg);
  printf("-----------------------------------------------------\n");
  printf("process:\n%s\n", msg);
  printf("result:\n");
  rc = j_val(pool, &p, tl, "");
  entry = (apr_table_entry_t *)apr_table_elts(tl)->elts;
  for(i = 0; i < apr_table_elts(tl)->nelts; i++) {
    printf(" [%s=%s]\n", entry[i].key, entry[i].val);
  }
  if(rc != APR_SUCCESS) {
    printf("ERROR\n");
  }
}

int main(int argc, const char *const argv[]) {
  apr_pool_t *pool;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  process(pool, data00);
  process(pool, data01);
  //process(pool, data01);
  //process(pool, data02);

  apr_pool_destroy(pool);
  return 0;
}
