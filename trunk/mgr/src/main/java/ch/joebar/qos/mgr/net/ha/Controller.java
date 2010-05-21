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
	private String listen;
	// how long we wait for udp packets
	private int counter = 3;

	public Controller(String iface, String mask, String[] addresses, 
			String listen, String peer) {
		this.peer = peer;
		this.listen = listen;
		try {
			this.l = new Listener(listen);
		} catch (UnknownHostException e) {
			log.info("init failed: " + e.toString());
		}
		if(listen.compareTo(peer) > 0) {
			this.counter = (this.counter * 2) + 1;
		}
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
		if(this.status.getState().equals(State.STANDBY) &&
				this.status.getRequest() != Transition.TRANSFER) {
			// TODO
			log.info(this.listen + ": change state to ACTIVE");
			this.setStatus(new Status(Connectivity.UP, State.ACTIVE, this.status.getRequest()));
		}
	}
	
	private void standby() {
		if(this.status.getState().equals(State.ACTIVE)) {
			// TODO
			log.info(this.listen + ": change state to STANDBY");
			this.setStatus(new Status(Connectivity.UP, State.STANDBY, this.status.getRequest()));
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
		this.status.setRequest(request);
		if(request == Transition.TRANSFER) {
			// become standby, peer will become active automatically
			this.standby();
		} else {
			// signalize only that we want to become active 
		}
	}
	
	public void run() {
		while(!Thread.interrupted()){
			try {
				Thread.sleep(Heartbeat.INTERVAL*this.counter);
			} catch (InterruptedException e) {
				return;
			}
			if(this.h == null) {
				this.initHeartbeat();
				this.start();
			}
			Status s = this.l.getPeerStatus();
			// clear transition
			if(this.status.getRequest() == Transition.TRANSFER) {
				if(s.getState() == State.ACTIVE) {
					// done
					this.status.setRequest(Transition.NOP);
				}
			}
			if(this.status.getRequest() == Transition.TAKEOVER) {
				if(this.status.getState() == State.ACTIVE) {
					this.status.setRequest(Transition.NOP);
				}
			}
			/* check connectivity:
			 * 1) become active, if peer is down
			 * 2) go down if peer is active
			 * 3) become active, if peer is standby 
			 * check transition:
			 * 4) become standby if peer indicates takeover
			 */
			if(s.getConnectivity().equals(Connectivity.DOWN)) {
				// 1)
				this.active();
			} else {
				if(s.getRequest() == Transition.TAKEOVER) {
					// 4
					this.standby();
				} else {
					if(s.getState().equals(State.ACTIVE)) {
						// 2
						this.standby();
					} else {
						// 3
						this.active();
					}
				}
			}
		}
	
	}
	
	public void end() {
		log.info(this.listen + ": end");
		this.lt.interrupt();
		this.ht.interrupt();
	}
}
