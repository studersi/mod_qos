/**
 * Converts GeoLite2 Country CSV files into the a format
 * which can be loaded by mod_qos.
 *
 * The GeoLite2-Country-CSV_<date>.zip archive contains
 * the IP range/block defintion file "GeoLite2-Country-Blocks-IPv4.csv"
 * as well as the ISO 3166 country code block mapping file
 * "GeoLite2-Country-Locations-en.csv".
 *
 * Copyright (C) 2019 Pascal Buchbinder
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

#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define MAX_LINE 32768

static void usage() {
  printf("usage: maxMindConvert <GeoLite2-Country-Blocks-IPv4.csv> <GeoLite2-Country-Locations-en.csv>\n");
  printf("\n");
  exit(1);
}

typedef struct {
  int w;
  int x;
  int y;
  int z;
} qs_mask_t;

static const qs_mask_t qs_mask[] = {
  { 255, 255, 255, 255 },
  { 255, 255, 255, 254 },
  { 255, 255, 255, 252 },
  { 255, 255, 255, 248 },
  { 255, 255, 255, 240 },
  { 255, 255, 255, 224 },
  { 255, 255, 255, 192 },
  { 255, 255, 255, 128 },
  { 255, 255, 255, 0 },
  { 255, 255, 254, 0 },
  { 255, 255, 252, 0 },
  { 255, 255, 248, 0 },
  { 255, 255, 240, 0 },
  { 255, 255, 224, 0 },
  { 255, 255, 192, 0 },
  { 255, 255, 128, 0 },
  { 255, 255, 0, 0 },
  { 255, 254, 0, 0 },
  { 255, 252, 0, 0 },
  { 255, 248, 0, 0 },
  { 255, 240, 0, 0 },
  { 255, 224, 0, 0 },
  { 255, 192, 0, 0 },
  { 255, 128, 0, 0 },
  { 255, 0, 0, 0 },
  { 254, 0, 0, 0 },
  { 252, 0, 0, 0 },
  { 248, 0, 0, 0 },
  { 240, 0, 0, 0 },
  { 224, 0, 0, 0 },
  { 192, 0, 0, 0 },
  { 128, 0, 0, 0 },
  { 0, 0, 0, 0 }
};

static int resolveCountry(FILE *file, int id, char *country_iso_code) {
  char line[MAX_LINE], raw[MAX_LINE];
  country_iso_code[0] = '\0';
  while(fgets(line, sizeof(line), file) != NULL) {
    if(strstr(line, "geoname_id") == NULL) {
      int geoname_id;
      char locale_code[32], continent_code[32];
      sscanf(line, "%d,%2s,%2s,%256c", &geoname_id,
	     locale_code, continent_code, raw);
      if(geoname_id == id) {
	char *next = strchr(raw, ',');
	if(next) {
	  sscanf(next, ",%2s,", country_iso_code);
	  if(country_iso_code[0] == ',') {
	    strcpy(country_iso_code, continent_code);
	  }
	  goto found;
	}
	fprintf(stderr, "ERROR, unexpected line %s\n", line);
	goto wrongSyntax;
      }
    }
  }

 wrongSyntax:
  fseek(file, 0, SEEK_SET);
  return 1;

 found:
  fseek(file, 0, SEEK_SET);
  return 0;
}

int main(int argc, const char * const argv[]) {
  FILE *blockFile;
  FILE *locationFile;
  char line[MAX_LINE];

  argc--;
  argv++;
  if(argc != 2) {
    usage();
  }
  blockFile = fopen(*argv, "r");
  if(!blockFile) {
    fprintf(stderr, "ERROR, failed to open block file '%s'\n", *argv);
    exit(1);
  }
  argv++;
  locationFile = fopen(*argv, "r");
  if(!locationFile) {
    fprintf(stderr, "ERROR, failed to open location file '%s'\n", *argv);
    exit(1);
  }

  while(fgets(line, sizeof(line), blockFile) != NULL) {
    char country_iso_code[32];
    int w,x,y,z,n;
    int geoname_id, registered_country_geoname_id,
      represented_country_geoname_id;
    sscanf(line, "%d.%d.%d.%d/%d,%d,%d,%d,", &w, &x, &y, &z, &n,
	   &geoname_id, &registered_country_geoname_id,
	   &represented_country_geoname_id);
    if(geoname_id > 0) {
      qs_mask_t m;
      if(resolveCountry(locationFile, geoname_id, country_iso_code) != 0) {
	fprintf(stderr, "ERROR, failed to resolve %d\n", geoname_id);
	exit(1);
      }
      m = qs_mask[32-n];
      printf("\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%.10u\",\"%.10u\",\"%s\"\n",
	     w & m.w, x & m.x, y & m.y, z & m.z,
	     (w & m.w) + (255-m.w), (x & m.x) + (255-m.x), (y & m.y) + (255-m.y), (z & m.z) + (255-m.z),
	     (w & m.w)*16777216 + (x & m.x)*65536 + (y & m.y)*256 + (z & m.z),
	     ((w & m.w) + (255-m.w))*16777216 + ((x & m.x) + (255-m.x))*65536 + ((y & m.y) + (255-m.y))*256 + ((z & m.z) + (255-m.z)),
	     country_iso_code);
    }
  }

  fclose(blockFile);
  fclose(locationFile);

  return 0;
}
