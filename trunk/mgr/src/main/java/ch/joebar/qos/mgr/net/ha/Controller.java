package ch.joebar.qos.mgr.net.ha;

import java.net.UnknownHostException;

public class Controller {
	
	private Listener l;
	private Heartbeat h;
	private Thread lt;
	private Thread ht;

	public Controller(String iface, String mask, String[] addresses, 
			String listen, String peer) {
		try {
			this.l = new Listener(listen);
			this.h = new Heartbeat(peer);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void start() {
		this.lt = new Thread(l);
		this.lt.start();
		this.ht = new Thread(h);
		this.ht.start();
	}
	
	private void active() {
		// TODO
		Status status = new Status(Status.STATUS_UP, Status.STATE_ACTIVE);
		this.h.setStatus(status);		
	}
	
	private void standby() {
		// TODO
		Status status = new Status(Status.STATUS_UP, Status.STATE_STANDBY);
		this.h.setStatus(status);		
	}
	
	public void run() throws InterruptedException {
		for(int i = 0; i < 5; i++) {
			Thread.sleep(Heartbeat.INTERVAL*3);
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
