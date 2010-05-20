package ch.joebar.qos.mgr.net.ha;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.log4j.Logger;

public class Listener implements Runnable {
	private static Logger log = Logger.getLogger(Heartbeat.class);

	public final static int UDP_PORT = 2619;
	private Status status = new Status(Status.STATUS_DOWN, Status.STATE_STANDBY);
	private InetAddress a;

	public Listener(String address) throws UnknownHostException {
		 this.a = InetAddress.getByName(address);
	}
	
	public void run() {
		try {
			DatagramSocket socket = new DatagramSocket(UDP_PORT, a);
			while(!Thread.interrupted()){
			    DatagramPacket packet = new DatagramPacket(new byte[512],512);
				socket.receive(packet);
				String received = new String(packet.getData(), 0, packet.getLength());
				System.out.println("$$$ [" + received + "]");
				// shared secret
				this.status = new Status(received);
			}
		} catch (IOException e) {
			log.error("failed to listen on " + this.a.getHostName() + ":" + Listener.UDP_PORT +
					", " + e.toString());
		}
	}

	/**
	 * Returns the status of the peer ha agent and reset the state.
	 * @return
	 */
	public Status getPeerStatus() {
		Status s = this.status;
		this.status = new Status(Status.STATUS_DOWN, Status.STATE_STANDBY);
		return s;
	}
}
