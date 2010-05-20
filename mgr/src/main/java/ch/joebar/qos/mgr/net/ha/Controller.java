package ch.joebar.qos.mgr.net.ha;

import java.net.UnknownHostException;

import org.apache.log4j.Logger;

public class Controller {
	private static Logger log = Logger.getLogger(Controller.class);
	
	private Status status = new Status(Status.STATUS_DOWN, Status.STATE_STANDBY); 
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
	
	public void start() {
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
	
	public void active() {
		if(this.status.getState().equals(Status.STATE_STANDBY)) {
			// TODO
			log.info("change state to ACTIVE");
			this.setStatus(new Status(Status.STATUS_UP, Status.STATE_ACTIVE));
		}
	}
	
	public void standby() {
		if(status.getState().equals(Status.STATE_ACTIVE)) {
			// TODO
			log.info("change state to STANDBY");
			this.setStatus(new Status(Status.STATUS_UP, Status.STATE_STANDBY));
		}
	}
	
	public void run() throws InterruptedException {
		for(int i = 0; i < 5; i++) {
			Thread.sleep(Heartbeat.INTERVAL*3);
			if(this.h == null) {
				this.initHeartbeat();
				this.start();
			}
			Status s = this.l.getPeerStatus();
			/* check connectivity
			 * 1) become active, if peer is down
			 * 2) go down if peer is active 
			 */
			if(s.getConnectivity().equals(Status.STATUS_DOWN)) {
				this.active();
			} else {
				if(s.getState().equals(Status.STATE_ACTIVE)) {
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
