package ch.joebar.qos.mgr.net.ha;

import java.net.UnknownHostException;

import org.apache.log4j.Logger;

public class Controller implements Runnable {
	private static Logger log = Logger.getLogger(Controller.class);
	
	private Status status = new Status(); 
	private Listener l = null;
	private Heartbeat h = null;
	private Thread lt = null;
	private Thread ht = null;
	private String peer;

	public Controller(String iface, String mask, String[] addresses, 
			String listen, String peer) {
		try {
			this.l = new Listener(listen);
		} catch (UnknownHostException e) {
			log.info("init failed: " + e.toString());
		}
		this.peer = peer;
		this.initHeartbeat();
		this.start();
	}

	private void initHeartbeat() {
		if(this.h == null) {
			try {
				this.h = new Heartbeat(this.peer);
			} catch (UnknownHostException e) {
				this.h = null;
				log.warn("can't start heartbeat to " + this.peer + "," + e.toString());
			}
		}
	}
	
	private void start() {
		if(this.l != null && this.lt == null) {
			this.lt = new Thread(l);
			this.lt.start();
		}
		if(this.h != null && this.ht == null) {
			this.ht = new Thread(h);
			this.ht.start();
		}
	}

	private void setStatus(Status s) {
		// set local status
		this.status = s;
		if(this.h != null) {
			// and send it to the peer
			this.h.setStatus(s);
		}
	}
	
	private void active() {
		if(this.status.getState().equals(State.STANDBY)) {
			// TODO
			log.info("change state to ACTIVE");
			this.setStatus(new Status(Connectivity.UP, State.ACTIVE, null));
		}
	}
	
	private void standby() {
		if(status.getState().equals(State.ACTIVE)) {
			// TODO
			log.info("change state to STANDBY");
			this.setStatus(new Status(Connectivity.UP, State.STANDBY, null));
		}
	}

	/**
	 * Indicates if this instance is currently active or standby.
	 * @return
	 */
	public boolean isActive() {
		if(this.status.getState() == State.ACTIVE) {
			return true;
		}
		return false;
	}
	
	/**
	 * Start transition to become active (takeover) or standby (transfer)
	 * @param request
	 */
	public void setTransition(Transition request) {
		// TODO
	}
	
	public void run() {
		while(!Thread.interrupted()){
			try {
				Thread.sleep(Heartbeat.INTERVAL*3);
			} catch (InterruptedException e) {
				return;
			}
			if(this.h == null) {
				this.initHeartbeat();
				this.start();
			}
			Status s = this.l.getPeerStatus();
			/* check connectivity
			 * 1) become active, if peer is down
			 * 2) go down if peer is active 
			 * check transition
			 * TODO
			 */
			if(s.getConnectivity().equals(Connectivity.DOWN)) {
				this.active();
			} else {
				if(s.getState().equals(State.ACTIVE)) {
						this.standby();
				} else {
					this.active();
				}
			}
		}
	
	}
	
	public void end() {
		this.lt.interrupt();
		this.ht.interrupt();
	}
}
