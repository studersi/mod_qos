package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Iterator;
import java.util.TreeSet;

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

public class Location extends Entry {

	private Entries entries = new Entries();

	Location(BufferedReader br, Line eline) throws IOException {
		super(null, eline);
		int end = eline.get().lastIndexOf(">");
		int del = eline.get().indexOf(" ");
		this.name = eline.get().substring(del, end).trim();
		this.name = this.trimQuotes(this.name);
		// read until the location end
		Line line = null;
		do {
			line = null;
			try {
				line = new Line(br);
				if(this.end(line)) {
					line = null;
					break;
				} else if(line.isDirective()) {
					Directive d = new Directive(br, line);
					this.entries.put(d);
				} else if(line.isInclude()) {
					// TODO
					Entry e = new Entry(br, line);
					this.entries.put(e);
				} else {
					Entry e = new Entry(br, line);
					this.entries.put(e);
				}
			} catch (IOException e) {
				// end of file
			}
		} while(line != null);
	}


	public Directives getDirectives() {
		return this.entries.getDirectives();
	}
	
	protected boolean end(Line line) {
		return line.isLocationEnd();
	}
	
	protected String tag() {
		return "Location";
	}
	
	public void save(PrintStream pm) {
		String q = "";
		if(this.name.contains(" ")) {
			q = "\"";
		}
		pm.println("<" + this.tag() + " " + q + this.name + q + ">");
		Iterator <String>i = this.entries.keySet().iterator();
		TreeSet<String> sm = new TreeSet<String>();
		while(i.hasNext()) {
			sm.add(i.next());
		}
		Iterator<String> it = sm.iterator();
		while(it.hasNext()) {
			this.entries.get(it.next()).save(pm);
		}
		pm.println("</" + this.tag() + ">");
	}

}
