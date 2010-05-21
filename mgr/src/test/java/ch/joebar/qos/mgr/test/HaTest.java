package ch.joebar.qos.mgr.test;

import org.apache.log4j.BasicConfigurator;

import junit.framework.TestCase;
import ch.joebar.qos.mgr.net.ha.Controller;
import ch.joebar.qos.mgr.net.ha.Transition;

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
		Thread t2 = new Thread(c2);
		t2.start();
		Thread.sleep(20000);

		c1.setTransition(Transition.TRANSFER);
		Thread.sleep(20000);

		c2.end();
		Thread.sleep(20000);
				
		c1.end();
		System.out.println("end");
	}
}
