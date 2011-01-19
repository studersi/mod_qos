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
