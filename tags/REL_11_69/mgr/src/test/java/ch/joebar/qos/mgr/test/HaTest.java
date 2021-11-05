package ch.joebar.qos.mgr.test;

import java.io.File;

import org.apache.log4j.BasicConfigurator;

import junit.framework.TestCase;
import ch.joebar.qos.mgr.net.ha.Controller;
import ch.joebar.qos.mgr.net.ha.Transition;

public class HaTest extends TestCase {

	public void testHeartbeat() throws Exception {
		long interval = 500;
		String cmd = "./src/test/bin/ha.sh";
		String log = "./src/test/bin/ha.log";
		File f = new File(log);
		if(f.exists()) {
			f.delete();
		}
	    BasicConfigurator.configure();
	    //PropertyConfigurator.configure(args[0]);
		System.out.println("start");
		String[] addresses1 = { "172.17.2.5", "172.17.2.6" };

		Controller c1 = new Controller(cmd, "eth2", "255.255.255.0", "172.17.2.255", "172.17.2.1",
				addresses1,
				"127.0.0.1", "127.0.0.2",
				"1234", interval);
		Controller c2 = new Controller(cmd, "eth2", "255.255.255.0", "172.17.2.255", "172.17.2.1",
				addresses1,
				"127.0.0.2", "127.0.0.1",
				"1234", interval);

		Thread t1 = new Thread(c1);
		t1.start();
		Thread t2 = new Thread(c2);
		t2.start();
		Thread.sleep(interval * (Controller.RATE * 2 + 5));
		if(c1.isActive() && c2.isActive()) {
			super.fail();
		}
		
		System.out.println("start transfer (c1 to c2)");
		c1.setTransition(Transition.TRANSFER);
		Thread.sleep(interval * (Controller.RATE * 2 + 5));
		if(c1.isActive() || !c2.isActive()) {
			super.fail();
		}

		System.out.println("start transfer (c2 to c1)");
		c2.setTransition(Transition.TRANSFER);
		Thread.sleep(interval * (Controller.RATE * 2 + 5));
		if(!c1.isActive() || c2.isActive()) {
			super.fail();
		}

		System.out.println("end controller 1 (automatic transfer from c1 to c2)");
		c1.end();
		Thread.sleep(interval * (Controller.RATE * 2 + 5));
		if(!c2.isActive()) {
			super.fail();
		}

		System.out.println("force transfer (broken link)");
		c2.setTransition(Transition.TRANSFER);
		Thread.sleep(interval * (Controller.RATE * 2 + 5) * 2);
		if(c2.isActive()) {
			super.fail();
		}

		System.out.println("force takeover (broken link)");
		c2.setTransition(Transition.TAKEOVER);
		Thread.sleep(interval * (Controller.RATE * 2 + 5));
		if(!c2.isActive()) {
			super.fail();
		}

		c2.end();
		System.out.println("end");
	}
}
