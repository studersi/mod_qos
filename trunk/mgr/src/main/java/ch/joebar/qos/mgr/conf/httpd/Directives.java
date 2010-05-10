package ch.joebar.qos.mgr.conf.httpd;

public class Directives extends Entries {
	
	public void put(Directive directive) {
		super.put(directive);
	}
	
	public Directive get(String key) {
		return (Directive) this.entries.get(key);
	}
	
}
