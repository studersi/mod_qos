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
