package ch.joebar.qos.mgr.net.ha;

import java.net.UnknownHostException;

public class Controller {
	
	private Thread l;
	private Thread h;

	public Controller(String iface, String mask, String[] addresses, 
			String listen, String peer) {
		try {
			this.l = new Thread(new Listener(listen));
			this.h = new Thread(new Heartbeat(peer));
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void start() {
		this.l.start();
		this.h.start();
	}
	
	public void end() {
		this.l.interrupt();
		this.h.interrupt();
	}
}
