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
