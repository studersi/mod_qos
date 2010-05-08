package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;

public class Entry extends Line {

	protected String name;

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
	
	public void save(PrintStream pm) {
		pm.println(this.line);
	}
}
