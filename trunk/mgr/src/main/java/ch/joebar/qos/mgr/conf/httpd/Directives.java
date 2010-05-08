package ch.joebar.qos.mgr.conf.httpd;

import java.util.HashMap;

public class Directives extends Entries {

	protected HashMap <String,Directive>entries = new HashMap<String, Directive>();
	
	public void put(Directive directive) {
		super.put(directive);
	}
	
	public Directive get(String key) {
		return this.entries.get(key);
	}
	
}
