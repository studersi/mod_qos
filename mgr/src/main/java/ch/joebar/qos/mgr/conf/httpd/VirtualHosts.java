package ch.joebar.qos.mgr.conf.httpd;

import java.util.HashMap;

public class VirtualHosts extends Entries {

	protected HashMap <String,VirtualHost>entries = new HashMap<String, VirtualHost>();
	
	public void put(VirtualHost host) {
		super.put(host);
	}
	
	public VirtualHost get(String key) {
		return this.entries.get(key);
	}
	
}
