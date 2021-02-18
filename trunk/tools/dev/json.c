/**
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2021 Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

static const char revision[] = "$Id$";

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

const char data00[] = " \"mein name (\\\"oder was\\\")\"";
const char data01[] = " { \"name\" : \"value\" , \"und noch\" : \"mehr text\" }";
const char data02[] = " { \"name\" : true , \"nummer\" : -1000e+12 }";
const char data10[] = " {\n" \
  "    \"name\": \"Jack (\\\"Bee\\\") Nimble\", \n"	\
  "    \"format\": {\n"					\
  "        \"type\":       \"rect\",\n"			\
  "\t\"width\":      1920, \n"			\
  "\t\"height\":     1080,\n"			\
  "        \"interlace\":  false, \n"			\
  "        \"frame rates\": [ 24 , 30 , 60, 72 ]\n"	\
  "    }\n"						\
  "}\n"							\
  "";
const char data11[] = "[\"Label 0\",{\"type\":\"Text\",\"label\":\"text label 1\",\"title\":\"this is the tooltip for text label 1\",\"editable\":true},{\"type\":\"Text\",\"label\":\"branch 1\",\"title\":\"there should be children here\",\"expanded\":true,\"children\":[\"Label 1-0\"]},{\"type\":\"Text\",\"label\":\"text label 2\",\"title\":\"this should be an href\",\"href\":\"http://www.yahoo.com\",\"target\":\"something\"},{\"type\":\"HTML\",\"html\":\"<a href=\\\"developer.yahoo.com/yui\\\">YUI</a>\",\"hasIcon\":false},{\"type\":\"MenuNode\",\"label\":\"branch 3\",\"title\":\"this is a menu node\",\"expanded\":false,\"children\":[\"Label 3-0\",\"Label 3-1\"]}]";
const char data12[] = "{"			\
  "     \"firstName\": \"John\",  \n"		\
  "     \"lastName\": \"Smith\",  \n"		\
  "     \"age\": 25,\n"				\
  "     \"address\": \n"			\
  "     {\n"					   \
  "         \"streetAddress\": \"21 2nd Street\",\n"	\
  "         \"city\": \"New York\",\n"			\
  "         \"state\": \"NY\",\n"			\
  "         \"postalCode\": \"10021\"\n"		\
  "     },  \n"						\
  "     \"phoneNumber\": \n"				\
  "     [\n"						\
  "         {\n"					\
  "           \"type\": \"home\",\n"			\
  "           \"number\": \"212 555-1234\"\n"		\
  "         },\n"					\
  "         {\n"					\
  "           \"type\": \"fax\\tnumber\",\n"			\
  "           \"number\": \"646 555-4567\"\n"		\
  "         }\n"					\
  "     ]\n"						\
  " }";

const char data13[] = "{\n" \
  "    \"_to\": \"1.2.3.4:5678\",\n"		\
  "    \"_line\": 63546230,\n"						\
  "    \"profile_image_url\": \"http://a3.twimg.com/profile_images/852841481/Untitled_3_normal.jpg\",\n" \
  "    \"created_at\": \"Sat, 08 May 2010 21:46:23 +0000\",\n"		\
  "    \"from_user\": \"pelchiie\",\n"					\
  "    \"metadata\": {\n"						\
  "        \"result_type\": \"recent\"\n"				\
  "    },\n"								\
  "    \"to_user_id\": null,\n"						\
  "    \"text\": \"twitter is dead today.\",\n"				\
  "    \"id\": 13630378882,\n"						\
  "    \"from_user_id\": 12621761,\n"					\
  "    \"geo\": null,\n"						\
  "    \"iso_language_code\": \"en\",\n"				\
  "    \"source\": \"<a href=\\\"http://twitter.com/\\\">web</a>\"\n"	\
  "}";
const char data20[] = "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ \"name\", 123 ]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]";
const char data21[] = "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ \"name\", 123 ]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]";
const char data30[] = " { \"name\" : true , \"nummer\" : -100fe+12 }";
const char data31[] = " { \"name \"first\"\" : true , \"nummer\" : -100e+12 }";
const char data32[] = "[ 2 ,3,4,5  ,  \t 9 ]";
const char data33[] = "[ 2 ,3,4 5  ,  \t 9 ]";


/* json parser start ------------------------------------------------------- */
#define QOS_J_ERROR "HTTP_BAD_REQUEST QOS JSON PARSER: FORMAT ERROR"
#define QOS_j_RECURSION 80

static int j_val(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, int rec);

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
  while(in[0] && ((in[0] == ' ') ||
		  (in[0] == '\t') ||
		  (in[0] == '\r') ||
		  (in[0] == '\n') ||
		  (in[0] == '\f'))) {
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

static int j_num(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, char **n) {
  char *s = *val;
  char *d = *val;
  while(d && ((d[0] >= '0' && d[0] <= '9') ||
	      d[0] == '.' ||
	      d[0] == 'e' ||
	      d[0] == 'E' ||
	      d[0] == '+' ||
	      d[0] == '-')) {
    d++;
  }
  *n = apr_pstrndup(pool, s, d-s);
  *val = d;
  return APR_SUCCESS;
}

static int j_obj(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, int rec) {
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
      thisname = apr_pstrcat(pool, name, "_" , v, NULL);
      d = j_skip(d);
      if(!d || d[0] != ':') {
	apr_table_add(tl, QOS_J_ERROR, "error while parsing object (missing value/wrong delimiter)");
	return HTTP_BAD_REQUEST;
      }
      d++;
      rc = j_val(pool, &d, tl, thisname, rec);
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
  }
  return APR_SUCCESS;
}

static int j_ar(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, int rec) {
  char *d = j_skip(*val);
  int rc;
  int index = 0;
  while(d && d[0]) {
    rc = j_val(pool, &d, tl, apr_psprintf(pool, "%s%d", name, index), rec);
    if(rc != APR_SUCCESS) {
      return rc;
    }
    d = j_skip(d);
    if(!d) {
      apr_table_add(tl, QOS_J_ERROR, "error while parsing array (unexpected end)");
      return HTTP_BAD_REQUEST;
    }
    if(d[0] == ']') {
      d++;
      *val = d;
      return APR_SUCCESS;
    } else if(d[0] == ',') {
      d++;
      d = j_skip(d);
    } else {
      apr_table_add(tl, QOS_J_ERROR, "error while parsing array (unexpected end/wrong delimiter)");
      return HTTP_BAD_REQUEST;
    }
    index++;
  }
  return APR_SUCCESS;
}

static int j_val(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, int rec) {
  char *d = j_skip(*val);
  int rc = APR_SUCCESS;
  rec++;
  if(rec > QOS_j_RECURSION) {
    apr_table_add(tl, QOS_J_ERROR, "error while parsing string (reached recursion limit)");
    return HTTP_BAD_REQUEST;
  }
  /* either object, array, string, number, "true", "false", or "null" */
  if(d[0] == '{') {
    d++;
    rc = j_obj(pool, &d, tl, apr_pstrcat(pool, name, "_o", NULL), rec);
  } else if(d[0] == '[') {
    d++;
    rc = j_ar(pool, &d, tl, apr_pstrcat(pool, name, "_a", NULL), rec);
  } else if(strncmp(d,"null",4) == 0) {
    d+=4;
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), "_b", NULL), "null");
  } else if(strncmp(d,"true",4) == 0) {
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), "_b", NULL), "true");
    d+=4;
  } else if(strncmp(d,"false",5) == 0) {
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), "_b", NULL), "false");
    d+=5;
  } else if(*d == '-' || (*d >= '0' && *d <= '9')) {
    char *n = apr_pstrcat(pool, name, "_n", NULL);
    char *v = NULL;
    rc = j_num(pool, &d, tl, n, &v);
    if(rc == APR_SUCCESS) {
      apr_table_addn(tl, j_escape_url(pool, n), j_escape_url(pool, v));
    }
  } else if(*d == '\"') {
    char *n = apr_pstrcat(pool, name, "_v", NULL);
    char *v = NULL;
    d++;
    rc = j_string(pool, &d, tl, n, &v);
    if(rc == APR_SUCCESS) {
      apr_table_addn(tl, j_escape_url(pool, n), j_escape_url(pool, v));
    }
  } else {
    /* error */
    apr_table_add(tl, QOS_J_ERROR, "error while parsing value (invalid type)");
    return HTTP_BAD_REQUEST;
  }
  if(rc != APR_SUCCESS) {
    return rc;
  }
  *val = d;
  rec--;
  return APR_SUCCESS;
}
/* json parser end --------------------------------------------------------- */

void process(apr_pool_t *pool, const char *msg, int expecterror) {
  char *res = NULL;
  int rc;
  apr_table_entry_t *entry;
  int i;
  char *p;
  apr_table_t *tl = apr_table_make(pool, 200);
  const char *err = NULL;
  p = apr_pstrdup(pool, msg);
  printf("-----------------------------------------------------\n");
  printf("process:\n%s\n", msg);
  printf("result:\n");
  rc = j_val(pool, &p, tl, "J", 0);
  entry = (apr_table_entry_t *)apr_table_elts(tl)->elts;
  err = apr_table_get(tl, QOS_J_ERROR);
  apr_table_unset(tl, QOS_J_ERROR);
  for(i = 0; i < apr_table_elts(tl)->nelts; i++) {
    if(res == NULL) {
      res = apr_pstrcat(pool, entry[i].key, "=", entry[i].val, NULL);
    } else {
      res = apr_pstrcat(pool, res, "&", entry[i].key, "=", entry[i].val, NULL);
    }
  }
  printf("/?%s\n", res ? res : "(null)");
  if(rc != APR_SUCCESS) {
    printf("ERROR: %s\n", err ? err : "-");
    if(!expecterror) {
      exit(1);
    }
  } else {
    if(expecterror) {
      printf("ERROR expected (but no one detected)\n");
      exit(1);
    }
  }
}

int main(int argc, const char *const argv[]) {
  apr_pool_t *pool;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  process(pool, data00, 0);
  process(pool, data01, 0);
  process(pool, data02, 0);
  process(pool, data10, 0);
  process(pool, data11, 0);
  process(pool, data12, 0);
  process(pool, data13, 0);
  process(pool, data20, 1);
  process(pool, data21, 0);
  process(pool, data30, 1);
  process(pool, data31, 1);
  process(pool, data32, 0);
  process(pool, data33, 1);

  apr_pool_destroy(pool);
  printf("-----------------------------------------------------\n");
  printf("normal end\n");
  return 0;
}
