package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
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

/**
 * Represents an Apache configuration file.
 */
public class Httpd {

	private Entries entries = new Entries();
	
	/**
	 * Creates a new configuration object based on an existing file.
	 * @param httpdConf path of the file to read the data from
	 * @throws IOException
	 */
	public Httpd(String httpdConf) throws IOException {
		FileInputStream s = new FileInputStream(httpdConf);
		DataInputStream ds = new DataInputStream(s);
		BufferedReader br = new BufferedReader(new InputStreamReader(ds));
		Line line = null;
		do {
			line = null;
			try {
				line = new Line(br);
				if(line.isLocation()) {
					Location l = new Location(br, line);
					this.entries.put(l);
				} else if(line.isLocationMatch()) {
					LocationMatch l = new LocationMatch(br, line);
					this.entries.put(l);
				} else if(line.isDirectory()) {
					Directory l = new Directory(br, line);
					this.entries.put(l);
				} else if(line.isVirtualHost()) {
					VirtualHost v = new VirtualHost(br, line);
					this.entries.put(v);
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
		
		br.close();
		ds.close();
		s.close();
	}
	
	public Locations getLocations() {
		return this.entries.getLocations();
	}

	public Directives getDirectives() {
		return this.entries.getDirectives();
	}
	
	public VirtualHosts getVirtualHosts() {
		return this.entries.getVirtualHosts();
	}
	
	/**
	 * Writes a file to the disk.
	 * @param httpdConf path of the file
	 * @throws IOException 
	 */
	public void save(String httpdConf) throws IOException {
		OutputStream out = new FileOutputStream(httpdConf);
		PrintStream pm = new PrintStream(out);
		this.save(pm, this.entries);
		out.close();
	}
	
	private void save(PrintStream pm, Entries e) {
		Iterator <String>i = e.keySet().iterator();
		TreeSet<String> sm = new TreeSet<String>();
		while(i.hasNext()) {
			sm.add(i.next());
		}
		Iterator<String> it = sm.iterator();
		while(it.hasNext()) {
			e.get(it.next()).save(pm);
		}		
	}
	
}
