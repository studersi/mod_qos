package ch.joebar.qos.mgr.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.StringTokenizer;

public class Ip {
	private long ip = 0;
	private long netmask = 0;
	private String netmaskStr = "";
	InetAddress a;
	
	/**
	 * New Ip obj.
	 * @param ip Ip address, e.g. 127.0.0.1
	 * @param netmask e.g. 255.255.255.0
	 */
	public Ip(String ip, String netmask) {
		this.ip = this.string2long(ip);
		this.netmask = this.string2long(netmask);
		this.netmaskStr = netmask;
	}

	public Ip(String hostname) throws UnknownHostException {
		this.a = InetAddress.getByName(hostname);
		String ip = this.a.getHostAddress();
		this.ip = this.string2long(ip);
	}
	
	public Ip(Long ip) {
		this.ip = ip;
	}

	public Long ip2long() {
		return new Long(this.ip);
	}
	
	public String long2ip() {
		return this.long2string(this.ip);
	}

	public String network() {
		return this.long2string(this.netmask & this.ip);
	}
	
	public boolean sameNetwork(String ip) {
		Ip i = new Ip(ip, this.netmaskStr);
		if(i.network().equals(this.network())) {
			return true;
		}
		return false;
	}

	private long string2long(String ip) {
		long _ip = 0;
		try {
			long m = 1;
			StringTokenizer st = new StringTokenizer(ip, ".");
			while(st.hasMoreElements()) {
				String t = st.nextToken();
				_ip = _ip + (m * new Long(t).longValue());
				m = m * 256;
			}
		} catch(Exception e) {
			return 0;
		}
		return _ip;
	}
	
	private String long2string(long i) {
		String ip = "";
		ip = ip + i % 256 + ".";
		i = i / 256;
		ip = ip + i % 256 + ".";
		i = i / 256;
		ip = ip + i % 256 + ".";
		i = i / 256;
		ip = ip + i % 256;
		return ip;
	}

}
