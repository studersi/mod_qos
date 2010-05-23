package ch.joebar.qos.mgr.net.ha;

import javax.crypto.SecretKey;

public class Message {

	private Status s = null;
	private SecretKey secretKey;
	private static final String MAGIC = "XDDMSG";
	
	public Message(SecretKey secretKey, Status status) {
		this.secretKey = secretKey;
		this.s = status;
	}
	
	public Message(SecretKey secret, String message) {
		String msg = Controller.decrypt(secret, message);
		//System.out.println("MSG <[" + msg + "]");
		if(msg != null && msg.startsWith(MAGIC)) {
			this.s = Status.d2i(msg);
		} else {
			System.out.println("$$$ ERROR dec");
		}
	}
	
	public Status getStatus() {
		return this.s;
	}
	
	public String getMessage() {
		String msg = MAGIC + ":" + Status.i2d(this.s); 
		//System.out.println("MSG >[" + msg + "]");
		return Controller.encrypt(this.secretKey, msg);
	}
}
