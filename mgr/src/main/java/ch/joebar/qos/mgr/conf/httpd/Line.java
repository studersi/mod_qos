package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * Represents a single line of the configuration file.
 */
public class Line {

	protected String line;
	
	/**
	 * Reads a line.
	 * @param br to read the line from
	 * @throws IOException on end of file
	 */
	Line(BufferedReader br) throws IOException {
		if(br != null) {
			String line = br.readLine();
			if(line == null) {
				throw new IOException();
			}
			while(line.endsWith("\\")) {
				String next = br.readLine();
				if(next != null) {
					line = line.substring(0, line.length()-1) + next;
				}
			}
			this.line = line.replace("\t", " ").trim();
		}
	}
	
	/**
	 * Raw line (trimmed)
	 * @return
	 */
	public String get() {
		return this.line;
	}
	
	public boolean isComment() {
		if(this.line.startsWith("#")) {
			return true;
		}
		return false;
	}
	
	public boolean isEmpty() {
		if(line.length() == 0) {
			return true;
		}
		return false;
	}

	public boolean isDirective() {
		return !this.isComment() &&
				!this.isEmpty() &&
				!this.isVirtualHost() &&
				!this.isLocation() &&
				!this.isLocationMatch() &&
				!this.isDirectory() &&
				!this.isInclude();
	}
	
	public boolean isInclude() {
		Pattern p = Pattern.compile("^[ \t]*Include[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}
	
	public boolean isVirtualHost() {
		Pattern p = Pattern.compile("^<[ \t]*VirtualHost[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isVirtualHostEnd() {
		Pattern p = Pattern.compile("^<[ \t]*/[ \t]*VirtualHost[ \t]*>.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}	
	
	public boolean isLocation() {
		Pattern p = Pattern.compile("^<[ \t]*Location[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isLocationEnd() {
		Pattern p = Pattern.compile("^<[ \t]*/[ \t]*Location[ \t]*>.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isLocationMatch() {
		Pattern p = Pattern.compile("^<[ \t]*LocationMatch[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isLocationMatchEnd() {
		Pattern p = Pattern.compile("^<[ \t]*/[ \t]*LocationMatch[ \t]*>.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isDirectory() {
		Pattern p = Pattern.compile("^<[ \t]*Directory[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isDirectoryEnd() {
		Pattern p = Pattern.compile("^<[ \t]*/[ \t]*Directory[ \t]*>.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}
}
