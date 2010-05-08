package ch.joebar.qos.mgr.conf.httpd;

import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Set;

public class Entries {

	protected HashMap <String,Entry>entries = new HashMap<String, Entry>();

	public void put(Entry entry) {
		DecimalFormat fmt = new DecimalFormat("0000");
		this.entries.put(fmt.format(this.entries.size()), entry);
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

}
