package ch.joebar.qos.mgr.conf.httpd;

import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

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

public class Entries {

	protected int key = 0;
	protected HashMap <String,Entry>entries = new HashMap<String, Entry>();

	public void put(Entry entry) {
		DecimalFormat fmt = new DecimalFormat("00000");
		String key = fmt.format(this.key);
		entry.setKey(key);
		this.entries.put(key, entry);
		this.key += 10;
	}
	
	public void set(Entry entry) {
		if(entry.getKey() == null) {
			this.put(entry);
		} else {
			this.entries.put(entry.getKey(), entry);
		}
	}
	
	public Entry get(String key) {
		return this.entries.get(key);
	}
	
	public int size() {
		return this.entries.size();
	}
	
	public Set<String> keySet() {
		return this.entries.keySet();
	}
	
	public void remove(String key) {
		this.entries.remove(key);
	}

	public void remove(Entry entry) {
		this.entries.remove(entry.getKey());
	}
	
	/**
	 * Returns all Location and LocationMatch entries
	 * @return
	 */
	public Locations getLocations() {
		Locations l = new Locations();
		Iterator <String>i = this.entries.keySet().iterator();
		while(i.hasNext()) {
			Entry entry = this.entries.get(i.next());
			if(entry instanceof LocationMatch) {
				l.put((LocationMatch)entry);
			} else if(entry instanceof Location) {
				l.put((Location)entry);
			}
		}
		return l;
	}

	public Directives getDirectives() {
		Directives d = new Directives();
		Iterator <String>i = this.entries.keySet().iterator();
		while(i.hasNext()) {
			Entry entry = this.entries.get(i.next());
			if(entry instanceof Directive) {
				d.put((Directive)entry);
			}
		}
		return d;
	}

	public VirtualHosts getVirtualHosts() {
		VirtualHosts v = new VirtualHosts();
		Iterator <String>i = this.entries.keySet().iterator();
		while(i.hasNext()) {
			Entry entry = this.entries.get(i.next());
			if(entry instanceof VirtualHost) {
				v.put((VirtualHost)entry);
			}
		}
		return v;		
	}

}
