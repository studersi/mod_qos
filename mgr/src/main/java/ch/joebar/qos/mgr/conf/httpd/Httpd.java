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
