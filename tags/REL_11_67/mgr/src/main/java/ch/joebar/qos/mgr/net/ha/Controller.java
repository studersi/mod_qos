package ch.joebar.qos.mgr.net.ha;

import java.net.UnknownHostException;
import javax.crypto.SecretKey;

import org.apache.log4j.Logger;
import ch.joebar.qos.mgr.util.CommandStarter;
import ch.joebar.qos.mgr.util.Crypto;

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
 * HA Controller 
 */
public class Controller implements Runnable {
	private static Logger log = Logger.getLogger(Controller.class);

	/** status of this instance */
	private Status status = new Status(Connectivity.UP, State.STANDBY, Transition.NOP); 
	private Listener l = null;
	private Heartbeat h = null;
	private Thread lt = null;
	private Thread ht = null;
	/** hostname/address of the peer node */
	private String peer;
	/** hostname/address of this instance */
	private String listen;
	
	/** how many times (Hearbeat.INTERVAL) we wait for udp packets until we decide
	 * that the peer is down due we don't receive any packets anymore */
	public static final int RATE = 2;
	private int counter = Controller.RATE;
	/** heartbeat interval */
	private static final long INTERVAL = 10000;
	private long interval = INTERVAL;

	/** command attributes (executed on status change) */
	private String cmd;
	private String iface;
	private String mask;
	private String[] addresses;
	private String bcast;
	private String gateway;
	
	/** shared secret for communication */
	private SecretKey secretKey;
	
	/**
	 * Creates a new controller and start a listener and heartbeat thread.
	 * 
	 * @param cmd Command to execute on state change (init, start, stop)
	 * @param iface Inteface name, e.g. eth0
	 * @param mask Netmask (required for plumbing the interface)
	 * @param bcast Broadcast address
	 * @param gateway Default gateway
	 * @param addresses Ip addresses to set for the sub interfaces
	 * @param listen Ip address (or hostname) we listen for heartbeat packages comming from the peer
	 * @param peer Ip Address (or hostname) of the peer node
	 * @throws UnknownHostException 
	 */
	public Controller(String cmd, String iface, String mask, String bcast, String gateway,
			String[] addresses, 
			String listen, String peer,
			String passphrase) throws UnknownHostException {
		this.create(cmd, iface, mask, bcast, gateway, addresses, listen, peer, 
				passphrase);
	}
	
	public Controller(String cmd, String iface, String mask, String bcast, String gateway,
			String[] addresses, 
			String listen, String peer,
			String passphrase, long interval) throws UnknownHostException {
		this.interval = interval;
		this.create(cmd, iface, mask, bcast, gateway, addresses, listen, peer, 
				passphrase);
	}

	private void create(String cmd, String iface, String mask, String bcast, String gateway,
			String[] addresses, 
			String listen, String peer,
			String passphrase) throws UnknownHostException {
		this.cmd = cmd;
		this.iface = iface;
		this.mask = mask;
		this.bcast = bcast;
		this.addresses = addresses;
		this.gateway = gateway;
		this.peer = peer;
		this.listen = listen;
		this.generateKey(passphrase);
		this.l = new Listener(listen, this.secretKey);
		log.info(this.listen + ": start");
		if(listen.compareTo(peer) > 0) {
			// ensure we don't resonate (the two controllers use different intervals) 
			this.counter = (this.counter * 2) + 1;
		}
		this.initCommand();
		this.standbyCommand(); // start at standby mode and become active, if peer is down or standby
		this.initHeartbeat();
		this.start();			
	}
	/**
	 * Init the heartbeat to send udp packets (instance starts even
	 * heartbeat init fails and tries to initialize it later).
	 */
	private void initHeartbeat() {
		if(this.h == null) {
			try {
				this.h = new Heartbeat(this.peer, this.secretKey, this.interval);
			} catch (UnknownHostException e) {
				this.h = null;
				log.warn("can't start heartbeat to " + this.peer + "," + e.toString());
			}
		}
	}
	
	/**
	 * Start listener (receiver) and heartbeat (sender).
	 */
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

	/**
	 * Updates the status of this instance.
	 * @param s
	 */
	private void setStatus(Status s) {
		// set local status
		this.status = s;
		if(this.h != null) {
			// and send it to the peer
			this.h.setStatus(s);
		}
	}
	
	/**
	 * Change state to active (start the interface and services).
	 * @throws InterruptedException 
	 */
	private void active() throws InterruptedException {
		if(this.status.getState().equals(State.STANDBY) &&
				this.status.getRequest() != Transition.TRANSFER) {
			log.info(this.listen + ": change state to ACTIVE");
			// inform peer first
			this.setStatus(new Status(Connectivity.UP, State.ACTIVE, this.status.getRequest()));
			Thread.sleep(this.interval);
			// then active interface and services
			this.activeCommand();
		}
	}
	
	/**
	 * Change state to standby (stop the interface).
	 * @throws InterruptedException 
	 */
	private void standby() throws InterruptedException {
		if(this.status.getState().equals(State.ACTIVE)) {
			log.info(this.listen + ": change state to STANDBY");
			// stop interface first
			this.standbyCommand();
			Thread.sleep(this.interval);
			// than inform peer about our status
			this.setStatus(new Status(Connectivity.UP, State.STANDBY, this.status.getRequest()));
		}
	}

	/**
	 * Command execution (either init, start or stop).
	 * @param action
	 */
	private void exec(String action) {
		String[] a = new String[this.addresses.length + 6];
		a[0] = this.cmd;
		a[1] = action;
		a[2] = this.iface;
		a[3] = this.mask;
		a[4] = this.bcast;
		a[5] = this.gateway;
		for(int i = 0; i < this.addresses.length; i++) {
			a[i+6] = this.addresses[i];
		}
		CommandStarter c = new CommandStarter(-1, 10000, 10000);
		c.callCommandToString(a);		
	}
	
	/**
	 * Inital setup command execution (plumb the interface).
	 */
	private void initCommand() {
		this.exec("init");
	}
	
	/**
	 * Executes the commands to become active (interface UP)
	 */
	private void activeCommand() {
		this.exec("start");
	}

	/**
	 * Executes the commands to become standby (interface DOWN)
	 */
	private void standbyCommand() {
		this.exec("stop");
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
	 * Start transition to become active (takeover) or standby (transfer).
	 * @param request
	 * @throws InterruptedException 
	 */
	public void setTransition(Transition request) throws InterruptedException {
		this.status.setRequest(request);
		if(request == Transition.TRANSFER) {
			// become standby, peer will become active automatically
			this.standby();
		} else {
			/* signalize only that we want to become active
			 * controller switches to standby as soon as the peer becomes active */
		}
	}
	
	/**
	 * Executes the controller which polls the status of the peer
	 * and controls the local state.
	 */
	public void run() {
		while(!Thread.interrupted()){
			try {
				Thread.sleep(this.interval*this.counter);
			} catch (InterruptedException e) {
				log.info("end controller (" + e.getMessage() + ")");
				return; // end controller
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
			try {
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
			} catch (InterruptedException e) {
				log.info("end controller (" + e.getMessage() + ")");
				return; // end controller
			}
		}
	
	}
	
	/**
	 * 3DES key from passphrase.
	 * @param passphrase
	 */
	private void generateKey(String passphrase) {
		this.secretKey = Crypto.generateKey(passphrase);
	}

	/**
	 * Stopps listener and heartbeat.
	 */
	public void end() {
		log.info(this.listen + ": end");
		this.lt.interrupt();
		this.ht.interrupt();
	}
}
