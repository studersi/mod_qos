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
 * Copyright (C) 2018 Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
