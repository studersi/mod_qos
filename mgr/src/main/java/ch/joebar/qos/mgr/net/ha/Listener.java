package ch.joebar.qos.mgr.net.ha;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.log4j.Logger;

/**
 * Listener is waiting for UDP packages from the peer server.
 */
public class Listener implements Runnable {
	private static Logger log = Logger.getLogger(Listener.class);

	public final static int UDP_PORT = 2619;
	private Status status = new Status(Status.STATUS_DOWN, Status.STATE_STANDBY);
	private InetAddress a;

	/**
	 * Resolve local address to listen.
	 * @param address
	 * @throws UnknownHostException
	 */
	public Listener(String address) throws UnknownHostException {
		 this.a = InetAddress.getByName(address);
	}
	
	/**
	 * Run the listener (until receiving an interrupt)
	 */
	public void run() {
		try {
			DatagramSocket socket = new DatagramSocket(UDP_PORT, a);
			while(!Thread.interrupted()){
			    DatagramPacket packet = new DatagramPacket(new byte[512],512);
				socket.receive(packet);
				String received = new String(packet.getData(), 0, packet.getLength());
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
	 * Call this method not more often than than every Heartbeat.INTERVAL milliseconds. 
	 * @return
	 */
	public Status getPeerStatus() {
		Status s = this.status;
		this.status = new Status(Status.STATUS_DOWN, Status.STATE_STANDBY);
		return s;
	}
}
