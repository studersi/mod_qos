package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;

/**
 * mod_qos, quality of service for web applications
 * 
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2018 Pascal Buchbinder
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

public class Entry extends Line {

	protected String name;
	protected String key = null;
	
	Entry(BufferedReader br, Line line) throws IOException {
		super(null);
		this.line = line.get();
		int del = this.line.indexOf(" "); 
		if(del != -1) {
			this.name = this.line.substring(0, del-1);
		} else {
			this.name = this.line;
		}
	}
	
	protected String trimQuotes(String s) {
		if(s.startsWith("\"") && s.endsWith("\"")) {
			return s.substring(1, s.length()-1).replace("\\\"", "\"");
		}
		if(s.startsWith("'") && s.endsWith("'")) {
			return s.substring(1, s.length()-1).replace("\\'", "'");
		}
		return s;
	}
	
	public String getName() {
		return this.name;
	}
	
	/**
	 * Key of the object within an Entries table of a Httpd, VirtualHost, Location object.
	 * @return
	 */
	public String getKey() {
		return this.key;
	}
	
	public void setKey(String key) {
		this.key = key;
	}
	
	public void save(PrintStream pm) {
		pm.println(this.line);
	}
}
