package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Iterator;
import java.util.TreeSet;

public class VirtualHost extends Entry {

	private Entries entries = new Entries();

	VirtualHost(BufferedReader br, Line eline) throws IOException {
		super(null, eline);
		int end = eline.get().lastIndexOf(">");
		int del = eline.get().indexOf(" ");
		this.name = eline.get().substring(del, end).trim();
		this.name = this.trimQuotes(this.name);
		// read until the vhost end
		Line line = null;
		do {
			line = null;
			try {
				line = new Line(br);
				if(line.isVirtualHostEnd()) {
					line = null;
					break;
				} else if(line.isLocation()) {
					Location l = new Location(br, line);
					this.entries.put(l);
				} else if(line.isLocationMatch()) {
					LocationMatch l = new LocationMatch(br, line);
					this.entries.put(l);
				} else if(line.isDirectory()) {
					Directory l = new Directory(br, line);
					this.entries.put(l);
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

	public Locations getLocations() {
		return this.entries.getLocations();
	}

	public Directives getDirectives() {
		return this.entries.getDirectives();
	}
	
	protected String tag() {
		return "VirtualHost";
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
