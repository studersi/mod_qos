package ch.joebar.qos.mgr.net.ha;

import java.net.UnknownHostException;

import org.apache.log4j.Logger;

/**
 * HA Controller 
 */
public class Controller implements Runnable {
	private static Logger log = Logger.getLogger(Controller.class);
	
	private Status status = new Status(); 
	private Listener l = null;
	private Heartbeat h = null;
	private Thread lt = null;
	private Thread ht = null;
	private String peer;
	private String listen;
	/** how many times (Hearbeat.INTERVAL) we wait for udp packets until we decide
	 * that the peer is down due we don't receive any packets anymore */
	private int counter = 3;

	/**
	 * Creates a new controller and start a listener and heartbeat thread.
	 * 
	 * @param iface Inteface name, e.g. eth0
	 * @param mask Netmask (required for plumbing the interface)
	 * @param addresses Ip addresses to set for the sub interfaces
	 * @param listen Ip address (or hostname) we listen for heartbeat packages comming from the peer
	 * @param peer Ip Address (or hostname) of the peer node
	 * @throws UnknownHostException 
	 */
	public Controller(String iface, String mask, String[] addresses, 
			String listen, String peer) throws UnknownHostException {
		this.peer = peer;
		this.listen = listen;
		this.l = new Listener(listen);
		log.info(this.listen + ": start");
		if(listen.compareTo(peer) > 0) {
			// ensure we don't resonate (the two controllers use different intervall) 
			this.counter = this.counter + 2;
		}
		this.initCommand();
		this.standbyCommand(); // start at standby mode and become active, if peer is down or standby
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
			log.info(this.listen + ": change state to ACTIVE");
			this.setStatus(new Status(Connectivity.UP, State.ACTIVE, this.status.getRequest()));
			try {
				Thread.sleep(Heartbeat.INTERVAL);
			} catch (InterruptedException e) {
				// nop
			}
			this.activeCommand();
		}
	}
	
	/**
	 * Inital setup command execution (plumb the interface).
	 */
	private void initCommand() {
		// TODO
	}
	
	/**
	 * Executes the commands to become active (interface UP)
	 */
	private void activeCommand() {
		// TODO
	}

	/**
	 * Executes the commands to become standby (interface DOWN)
	 */
	private void standbyCommand() {
		// TODO		
	}

	private void standby() {
		if(this.status.getState().equals(State.ACTIVE)) {
			// TODO
			this.standbyCommand();
			try {
				Thread.sleep(Heartbeat.INTERVAL);
			} catch (InterruptedException e) {
				// nop
			}
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
			/* signalize only that we want to become active
			 * controller switches to standby as soon as the peer becomes active */
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
			
			/* clear transition */
			if(this.status.getRequest() == Transition.TRANSFER) {
				if(s.getState() == State.ACTIVE) {
					// done, peer is now active
					this.status.setRequest(Transition.NOP);
				}
			}
			if(this.status.getRequest() == Transition.TAKEOVER) {
				if(this.status.getState() == State.ACTIVE) {
					// done, this instance is now active
					this.status.setRequest(Transition.NOP);
				}
			}
			
			/* check connectivity:
			 * 1) become active, if peer is down
			 * 2) go down if peer is active
			 * 3) become active, if peer is standby 
			 * check for peer's transition request:
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
