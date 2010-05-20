package ch.joebar.qos.mgr.net.ha;

public class Status {

	public final static String STATUS_UP = "UP";
	public final static String STATUS_DOWN = "DOWN";
	public final static String STATE_ACTIVE = "ACTIVE";
	public final static String STATE_STANDBY = "STANDBY";
	
	private String connectivity = STATUS_DOWN;
	private String state = STATE_STANDBY;
	
	public Status(String connectivity, String state) {
		this.connectivity = connectivity;
		this.state = state;
	}

	public Status(String received) {
		if(received.contains(STATUS_UP)) {
			this.connectivity = STATUS_UP;
		}
		if(received.contains(STATE_ACTIVE)) {
			this.state = STATE_ACTIVE;
		}
	}
	
	public String getConnectivity() {
		return this.connectivity;
	}
	
	public String getState() {
		return this.state;
	}
	
}
