package ch.joebar.qos.mgr.test;

import junit.framework.TestCase;
import ch.joebar.qos.mgr.net.ha.Controller;

public class HaTest extends TestCase {

	public void testHeartbeat() throws Exception {
		System.out.println("start");
		String[] addresses = { "127.0.0.3", "127.0.0.4" };

		Controller c1 = new Controller("lo", "255.0.0.0", addresses,
				"127.0.0.1", "127.0.0.2");
		Controller c2 = new Controller("lo", "255.0.0.0", addresses,
				"127.0.0.2", "127.0.0.1");
		c1.start();
		c2.start();
		
		c1.run();
		
		System.out.println("end");
		c1.end();
		c2.end();
	}
}
