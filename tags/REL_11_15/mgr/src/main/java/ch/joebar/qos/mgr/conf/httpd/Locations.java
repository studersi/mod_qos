package ch.joebar.qos.mgr.conf.httpd;

public class Locations extends Entries {
	
	public void put(Location location) {
		this.entries.put(location.getName(), location);
	}
	
	public void put(LocationMatch location) {
		this.entries.put(location.getName(), location);
	}
	
	public Location get(String key) {
		return (Location) this.entries.get(key);
	}
}
