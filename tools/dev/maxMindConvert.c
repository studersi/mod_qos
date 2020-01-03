/**
 * Converts GeoLite2 Country CSV files into the a format
 * which can be loaded by mod_qos.
 *
 * The GeoLite2-Country-CSV_<date>.zip archive contains the 
 * IP range/block defintion file "GeoLite2-Country-Blocks-IPv4.csv"
 * as well as the ISO 3166 country code block mapping file
 * "GeoLite2-Country-Locations-en.csv".
 * This tool merges those two files into one by adding the
 * country code to each IP range definition.
 *
 * Copyright (C) 2020 Pascal Buchbinder
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
  int id;
  char code[3];
} qs_location_t;

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

static qs_location_t *loadCountry(FILE *file, int *locationTableSize) {
  qs_location_t *locationTable = NULL;
  char line[MAX_LINE], raw[MAX_LINE];
  char country_iso_code[32];
  int position = 0;
  while(fgets(line, sizeof(line), file) != NULL) {
    position++;
  }
  fseek(file, 0, SEEK_SET);
  locationTable = calloc(position, sizeof(qs_location_t));
  position = 0;
  while(fgets(line, sizeof(line), file) != NULL) {
    if(strstr(line, "geoname_id") == NULL) {
      char *next;
      int geoname_id;
      char locale_code[32], continent_code[32];
      country_iso_code[0] = '\0';
      sscanf(line, "%d,%2s,%2s,%256c", &geoname_id,
	     locale_code, continent_code, raw);
      next = strchr(raw, ',');
      if(next) {
	sscanf(next, ",%2s,", country_iso_code);
	if(country_iso_code[0] == ',') {
	  strncpy(country_iso_code, continent_code, 2);
	}
	locationTable[position].id = geoname_id;
	strncpy(locationTable[position].code, country_iso_code, 2);
	position++;
      }
    }
  }
  *locationTableSize = position;
  return locationTable;
}

static const char *resolveCountry(qs_location_t * locationTable, int locationTableSize, int id) {
  int position = 0;
  while(position < locationTableSize) {
    if(locationTable[position].id == id) {
      return locationTable[position].code;
    }
    position++;
  }
  return NULL;
}

int main(int argc, const char * const argv[]) {
  FILE *blockFile;
  FILE *locationFile;
  char line[MAX_LINE];

  qs_location_t *locationTable = NULL;
  int locationTableSize = 0;

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
  locationTable = loadCountry(locationFile, &locationTableSize);
  fclose(locationFile);
  if(locationTableSize < 1) {
    fprintf(stderr, "ERROR, failed to read location file '%s'\n", *argv);
    exit(1);
  }

  while(fgets(line, sizeof(line), blockFile) != NULL) {
    int w,x,y,z,n;
    int geoname_id, registered_country_geoname_id,
      represented_country_geoname_id;
    sscanf(line, "%d.%d.%d.%d/%d,%d,%d,%d,", &w, &x, &y, &z, &n,
	   &geoname_id, &registered_country_geoname_id,
	   &represented_country_geoname_id);
    if(geoname_id > 0) {
      qs_mask_t m;
      const char *country_iso_code = resolveCountry(locationTable, locationTableSize, geoname_id);
      if(country_iso_code == NULL) {
	fprintf(stderr, "ERROR, failed to resolve id %d\n", geoname_id);
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

  return 0;
}
