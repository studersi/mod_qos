package ch.joebar.qos.mgr.test;

import org.apache.log4j.BasicConfigurator;

import junit.framework.TestCase;
import ch.joebar.qos.mgr.net.ha.Controller;

public class HaTest extends TestCase {

	public void testHeartbeat() throws Exception {
	    BasicConfigurator.configure();
	    //PropertyConfigurator.configure(args[0]);
		System.out.println("start");
		String[] addresses = { "127.0.0.3", "127.0.0.4" };

		Controller c1 = new Controller("lo", "255.0.0.0", addresses,
				"127.0.0.1", "127.0.0.2");
		Controller c2 = new Controller("lo", "255.0.0.0", addresses,
				"127.0.0.2", "127.0.0.1");
		Thread t1 = new Thread(c1);
		t1.start();
		for(int i = 0; i < 10; i++) {
			Thread.sleep(1000);
		}
		
		System.out.println("end");
		c1.end();
		c2.end();
	}
}
