package ch.joebar.qos.mgr.net.ha;

import javax.crypto.SecretKey;

import org.apache.log4j.Logger;

import ch.joebar.qos.mgr.util.Crypto;

/**
 * Messages are string representations of the instance status to be transmitted
 * to the peer as an udp packet. 
 *
 */
public class Message {
	private static Logger log = Logger.getLogger(Message.class);

	private Status s = null;
	private SecretKey secretKey;
	private static final String MAGIC = "QOSHAMSG";
	
	/**
	 * Now message based on the current local status.
	 * @param secretKey
	 * @param status
	 */
	public Message(SecretKey secretKey, Status status) {
		this.secretKey = secretKey;
		this.s = status;
	}
	
	/**
	 * New message based on received message data.
	 * @param secret
	 * @param message
	 */
	public Message(SecretKey secret, String message) {
		String msg = Crypto.decrypt(secret, message);
		log.trace("msg r< " + msg);
		if(msg != null && msg.startsWith(MAGIC)) {
			this.s = Status.d2i(msg);
		} else {
			log.debug("failed to read message (no magic): '" + msg + "'");
		}
	}
	
	/**
	 * Get the received status (may be null if status message was not valid).
	 * @return
	 */
	public Status getStatus() {
		return this.s;
	}
	
	/**
	 * Create a message string from the local status.
	 * @return
	 */
	public String getMessage() {
		String msg = MAGIC + ":" + Status.i2d(this.s); 
		log.trace("msg s> " + msg);
		return Crypto.encrypt(this.secretKey, msg);
	}
}
