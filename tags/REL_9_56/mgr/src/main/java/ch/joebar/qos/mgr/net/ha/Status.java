package ch.joebar.qos.mgr.net.ha;

public class Status {

	private final static String STATUS_UP = "UP";
	private final static String STATUS_DOWN = "DOWN";
	private final static String STATE_ACTIVE = "ACTIVE";
	private final static String STATE_STANDBY = "STANDBY";
	private final static String TRANSITION_TAKEOVER = "TAKEOVER";
	private final static String TRANSITION_TRANSFER = "TRANSFER";
	
	private Connectivity connectivity = Connectivity.DOWN;
	private State state = State.STANDBY;
	private Transition request = Transition.NOP;
	
	
	/**
	 * New status object.
	 * @param connectivity Indicates availability
	 * @param state State, either active or standby
	 * @param request Request to change state (becomming active or standby)
	 */
	public Status(Connectivity connectivity, State state, Transition request) {
		this.connectivity = connectivity;
		this.state = state;
		this.request = request == null ? Transition.NOP : request;
	}

	public Status() {
	}

	public void setRequest(Transition request) {
		this.request = request;
	}
	
	public Transition getRequest() {
		return this.request;
	}
	
	/**
	 * Returns the connectivity
	 * @return either STATUS_UP or STATUS_DOWN
	 */
	public Connectivity getConnectivity() {
		return this.connectivity;
	}
	
	/**
	 * Returns the state
	 * @return either STATE_ACTIVE or STATE_STANDBY
	 */
	public State getState() {
		return this.state;
	}

	/**
	 * De-serializes object
	 * @param received
	 * @return
	 */
	public static Status d2i(String received) {
		Status s = new Status();
		if(received.contains(STATUS_UP)) {
			s.connectivity = Connectivity.UP;
		}
		if(received.contains(STATE_ACTIVE)) {
			s.state = State.ACTIVE;
		}
		if(received.contains(TRANSITION_TAKEOVER)) {
			s.request = Transition.TAKEOVER;
		}
		if(received.contains(TRANSITION_TRANSFER)) {
			s.request = Transition.TRANSFER;
		}
		return s;
	}

	/**
	 * Serializes object.
	 * @param s
	 * @return
	 */
	public static String i2d(Status s) {
		String m = "";
		if(s.getState() == State.ACTIVE) {
			m += STATE_ACTIVE;
		} else {
			m += STATE_STANDBY;
		}
		if(s.getConnectivity() == Connectivity.UP) {
			m += ":" + STATUS_UP;
		} else {
			m += ":" + STATUS_DOWN;
		}
		if(s.getRequest() == Transition.TRANSFER) {
			m += ":" + TRANSITION_TRANSFER;
 		} else if(s.getRequest() == Transition.TAKEOVER) {
 			m += ":" + TRANSITION_TAKEOVER;
 		}
		return m;
	}
	
}
