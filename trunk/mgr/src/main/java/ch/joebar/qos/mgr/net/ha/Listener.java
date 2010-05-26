package ch.joebar.qos.mgr.net.ha;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.crypto.SecretKey;

import org.apache.log4j.Logger;

/**
 * mod_qos, quality of service for web applications
 * 
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2010 Pascal Buchbinder
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

/**
 * Listener is waiting for UDP packages from the peer server.
 */
public class Listener implements Runnable {
	private static Logger log = Logger.getLogger(Listener.class);

	//public final static int UDP_PORT = 694;
	public final static int UDP_PORT = 2694;
	private Status status = new Status();
	private InetAddress a;
	private SecretKey secretKey;

	/**
	 * Resolve local address to listen.
	 * @param address
	 * @param secretKey 
	 * @param interval 
	 * @throws UnknownHostException
	 */
	public Listener(String address, SecretKey secretKey) throws UnknownHostException {
		this.secretKey = secretKey;
		this.a = InetAddress.getByName(address);
	}
	
	/**
	 * Run the listener (until receiving an interrupt)
	 */
	public void run() {
		 String ip = this.a.getHostAddress();
		 log.debug("listen at " + ip);
		try {
			DatagramSocket socket = new DatagramSocket(UDP_PORT, a);
			while(!Thread.interrupted()){
			    DatagramPacket packet = new DatagramPacket(new byte[512],512);
				socket.receive(packet);
				String received = new String(packet.getData(), 0, packet.getLength());
				Message m = new Message(this.secretKey, received);
				Status t = m.getStatus();
				if(t != null) {
					this.status = t;
				}
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
		this.status = new Status();
		return s;
	}
}
