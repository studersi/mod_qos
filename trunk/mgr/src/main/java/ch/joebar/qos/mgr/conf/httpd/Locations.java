package ch.joebar.qos.mgr.conf.httpd;

import java.util.HashMap;

public class Locations extends Entries {

	protected HashMap <String,Location>entries = new HashMap<String, Location>();
	
	public void put(Location location) {
		this.entries.put(location.getName(), location);
	}
	
	public Location get(String key) {
		return this.entries.get(key);
	}
}
