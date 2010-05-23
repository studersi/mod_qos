package ch.joebar.qos.mgr.net.ha;

import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import ch.joebar.qos.mgr.util.CommandStarter;

/**
 * HA Controller 
 */
public class Controller implements Runnable {
	private static Logger log = Logger.getLogger(Controller.class);
	private static int RANLEN = 10;

	private Status status = new Status(); 
	private Listener l = null;
	private Heartbeat h = null;
	private Thread lt = null;
	private Thread ht = null;
	private String peer;
	private String listen;
	/** how many times (Hearbeat.INTERVAL) we wait for udp packets until we decide
	 * that the peer is down due we don't receive any packets anymore */
	private int counter = 3;

	private String cmd;
	private String iface;
	private String mask;
	private String[] addresses;
	private String bcast;
	private String gateway;
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
			String listen, String peer) throws UnknownHostException {
		this.cmd = cmd;
		this.iface = iface;
		this.mask = mask;
		this.bcast = bcast;
		this.addresses = addresses;
		this.gateway = gateway;
		this.peer = peer;
		this.listen = listen;
		this.generateKey("1234"); // TODO
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

	private void initHeartbeat() {
		if(this.h == null) {
			try {
				this.h = new Heartbeat(this.peer, this.secretKey);
			} catch (UnknownHostException e) {
				this.h = null;
				log.warn("can't start heartbeat to " + this.peer + "," + e.toString());
			}
		}
	}
	
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

	private void setStatus(Status s) {
		// set local status
		this.status = s;
		if(this.h != null) {
			// and send it to the peer
			this.h.setStatus(s);
		}
	}
	
	private void active() {
		if(this.status.getState().equals(State.STANDBY) &&
				this.status.getRequest() != Transition.TRANSFER) {
			log.info(this.listen + ": change state to ACTIVE");
			this.setStatus(new Status(Connectivity.UP, State.ACTIVE, this.status.getRequest()));
			try {
				Thread.sleep(Heartbeat.INTERVAL);
			} catch (InterruptedException e) {
				// nop
			}
			this.activeCommand();
		}
	}
	
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

	private void standby() {
		if(this.status.getState().equals(State.ACTIVE)) {
			// TODO
			this.standbyCommand();
			try {
				Thread.sleep(Heartbeat.INTERVAL);
			} catch (InterruptedException e) {
				// nop
			}
			log.info(this.listen + ": change state to STANDBY");
			this.setStatus(new Status(Connectivity.UP, State.STANDBY, this.status.getRequest()));
		}
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
	 * Start transition to become active (takeover) or standby (transfer)
	 * @param request
	 */
	public void setTransition(Transition request) {
		this.status.setRequest(request);
		if(request == Transition.TRANSFER) {
			// become standby, peer will become active automatically
			this.standby();
		} else {
			/* signalize only that we want to become active
			 * controller switches to standby as soon as the peer becomes active */
		}
	}
	
	public void run() {
		while(!Thread.interrupted()){
			try {
				Thread.sleep(Heartbeat.INTERVAL*this.counter);
			} catch (InterruptedException e) {
				return;
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
		}
	
	}
		
	public static String encrypt(SecretKey key, String value) {
        String enc = null;
        return value;
        /*
        SecureRandom srn = new SecureRandom();
        byte[] bytes = srn.generateSeed(Controller.RANLEN*2);
        String rnd = new String(Base64.encodeBase64(bytes)).substring(0, Controller.RANLEN);
        try {
        	IvParameterSpec params = new IvParameterSpec(new byte[] { 33, 83, 95, 66, 20, 15, 11, 93 });
        	Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        	cipher.init(Cipher.ENCRYPT_MODE, key, params);
        	byte[] raw = new String(rnd + value).getBytes();
        	byte[] cipherText = new byte[cipher.getOutputSize(raw.length)];
        	int ctLength = cipher.update(raw, 0, raw.length, cipherText, 0);
        	ctLength += cipher.doFinal(cipherText, ctLength);
        	enc = new String(Base64.encodeBase64(cipherText));
        } catch (Exception e) {
        	log.debug("could not encrypt value", e);
        }
        return enc;
        */
	}
	
	public static String decrypt(SecretKey key, String value) {
		String dec = null;
		return value;
		/*
		try {
			IvParameterSpec params = new IvParameterSpec(new byte[] { 33, 83, 95, 66, 20, 15, 11, 93 });
			Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, params);
			byte[] cipherText = Base64.decodeBase64(value.getBytes());
			int ctLength = cipherText.length;
			byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
			int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
			ptLength += cipher.doFinal(plainText, ptLength);
			String all = new String(plainText);
			if(all.length() > Controller.RANLEN) {
				dec = all.substring(Controller.RANLEN);
			}
		} catch (Exception e) {
			log.debug("could not decrypt value", e);
		}
		return dec;
		*/
	}
	
	private void generateKey(String passphrase) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(passphrase.getBytes());
			byte[] mdbytes = md.digest();
			/* add some bytes (des key requires 24 bytes) */
			/* IMPORTANT: never change these constants!!! */
			String key_seed = new String(mdbytes) + "lkjd8_.F48kaD700nh_sjchTTTa7sd5Hbbbbbd";
            DESedeKeySpec spec = new DESedeKeySpec(key_seed.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            this.secretKey = keyFactory.generateSecret(spec);
		} catch (Exception e) {
			log.error("could not create key: " + e.toString());
        }
	}
	
	public void end() {
		log.info(this.listen + ": end");
		this.lt.interrupt();
		this.ht.interrupt();
	}
}
