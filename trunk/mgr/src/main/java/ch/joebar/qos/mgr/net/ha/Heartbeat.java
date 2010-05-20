package ch.joebar.qos.mgr.net.ha;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.log4j.Logger;

/**
 * Sends heartbeat UDP packet every INTERVAL milliseconds.
 */
public class Heartbeat implements Runnable {
	private static Logger log = Logger.getLogger(Heartbeat.class);

	public static final long INTERVAL = 1000;
	private InetAddress a;
	private Status status = new Status(Status.STATUS_DOWN, Status.STATE_STANDBY);
	
	/**
	 * Resolves peer address.
	 * @param address
	 * @throws UnknownHostException
	 */
	public Heartbeat(String address) throws UnknownHostException {
		 this.a = InetAddress.getByName(address);
	}
	
	/**
	 * Starts the heartbeat (until receiving an interrupt)
	 */
	public void run() {
		while(!Thread.interrupted()){
			String m = status.getConnectivity() + ":" + status.getState();
			byte[]  message = m.getBytes();
		    DatagramPacket packet = new DatagramPacket(message, message.length, this.a, Listener.UDP_PORT);
			DatagramSocket dsocket;
			try {
				dsocket = new DatagramSocket();
				dsocket.send(packet);
				dsocket.close();
			} catch (IOException e) {
				log.warn("failed to send packet to " + a.getHostName() + ":" + Listener.UDP_PORT +
						", " + e.toString());
			}
			try {
				Thread.sleep(INTERVAL);
			} catch (InterruptedException e) {
				return;
			}
		}
	}

	/**
	 * Status of the local server (this is the value we send to the peer).
	 * @param status
	 */
	public void setStatus(Status status)  {
		this.status = status;
	}
	
	/**
	 * Current status of the local server.
	 * @return
	 */
	public Status getStatus() {
		return this.status;
	}
}
