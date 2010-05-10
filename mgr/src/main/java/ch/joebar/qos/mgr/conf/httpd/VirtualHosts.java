package ch.joebar.qos.mgr.conf.httpd;

public class VirtualHosts extends Entries {
	
	public void put(VirtualHost host) {
		super.put(host);
	}
	
	public VirtualHost get(String key) {
		return (VirtualHost) this.entries.get(key);
	}
	
}
