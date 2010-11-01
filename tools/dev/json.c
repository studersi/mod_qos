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

static const char revision[] = "$Id: json.c,v 1.1 2010-11-01 20:10:10 pbuchbinder Exp $";

/* system */
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* apr */
#include <apr_base64.h>
#include <apr_strings.h>

const char data01[] = "{\n" \
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

int main(int argc, const char *const argv[]) {
  apr_pool_t *pool;
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  printf("%s", data01);

  apr_pool_destroy(pool);
  return 0;
}

