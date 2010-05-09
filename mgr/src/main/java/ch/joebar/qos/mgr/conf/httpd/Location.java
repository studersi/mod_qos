package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Iterator;
import java.util.TreeSet;

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
