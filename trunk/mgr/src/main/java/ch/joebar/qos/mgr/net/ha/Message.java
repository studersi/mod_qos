package ch.joebar.qos.mgr.net.ha;

public class Message {

	private Status s;
	private String secret;
	
	public Message(String secret, Status status) {
		this.secret = secret;
		this.s = status;
	}
	
	public Message(String secret, String message) {
		// TODO decrypt
		this.s = Status.d2i(message);
	}
	
	public Status getStatus() {
		return this.s;
	}
	
	public String getMessage() {
		// TODO encrypt with shared secret
		return Status.i2d(this.s);
	}
}
