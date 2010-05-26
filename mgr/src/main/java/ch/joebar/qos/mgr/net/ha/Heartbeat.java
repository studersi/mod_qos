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
 * Sends heartbeat UDP packet every INTERVAL milliseconds.
 */
public class Heartbeat implements Runnable {
	private static Logger log = Logger.getLogger(Heartbeat.class);

	private InetAddress a;
	private Status status = new Status(Connectivity.UP, State.STANDBY, Transition.NOP); 
	private SecretKey secretKey;
	private long interval;

	
	/**
	 * Resolves peer address.
	 * @param address
	 * @param secretKey 
	 * @throws UnknownHostException
	 */
	public Heartbeat(String address, SecretKey secretKey, long interval) throws UnknownHostException {
		this.secretKey = secretKey;
		this.interval = interval;
		this.a = InetAddress.getByName(address);
	}
	
	/**
	 * Starts the heartbeat (until receiving an interrupt)
	 */
	public void run() {
		 String ip = this.a.getHostAddress();
		 log.debug("start heartbeat to " + ip);
		 while(!Thread.interrupted()){
			byte[] message = new Message(this.secretKey, this.status).getMessage().getBytes();
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
				Thread.sleep(this.interval);
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
