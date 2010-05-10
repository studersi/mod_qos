package ch.joebar.qos.mgr.conf.httpd;

import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

public class Entries {

	protected int key = 0;
	protected HashMap <String,Entry>entries = new HashMap<String, Entry>();

	public void put(Entry entry) {
		DecimalFormat fmt = new DecimalFormat("00000");
		String key = fmt.format(this.key);
		entry.setKey(key);
		this.entries.put(key, entry);
		this.key += 10;
	}
	
	public void set(Entry entry) {
		if(entry.getKey() == null) {
			this.put(entry);
		} else {
			this.entries.put(entry.getKey(), entry);
		}
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

	public void remove(Entry entry) {
		this.entries.remove(entry.getKey());
	}
	
	/**
	 * Returns all Location and LocationMatch entries
	 * @return
	 */
	public Locations getLocations() {
		Locations l = new Locations();
		Iterator <String>i = this.entries.keySet().iterator();
		while(i.hasNext()) {
			Entry entry = this.entries.get(i.next());
			if(entry instanceof LocationMatch) {
				l.put((LocationMatch)entry);
			} else if(entry instanceof Location) {
				l.put((Location)entry);
			}
		}
		return l;
	}

	public Directives getDirectives() {
		Directives d = new Directives();
		Iterator <String>i = this.entries.keySet().iterator();
		while(i.hasNext()) {
			Entry entry = this.entries.get(i.next());
			if(entry instanceof Directive) {
				d.put((Directive)entry);
			}
		}
		return d;
	}

	public VirtualHosts getVirtualHosts() {
		VirtualHosts v = new VirtualHosts();
		Iterator <String>i = this.entries.keySet().iterator();
		while(i.hasNext()) {
			Entry entry = this.entries.get(i.next());
			if(entry instanceof VirtualHost) {
				v.put((VirtualHost)entry);
			}
		}
		return v;		
	}

}
