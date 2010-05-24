package ch.joebar.qos.mgr.test;

import java.io.File;

import org.apache.log4j.BasicConfigurator;

import junit.framework.TestCase;
import ch.joebar.qos.mgr.net.ha.Controller;
import ch.joebar.qos.mgr.net.ha.Transition;

public class HaTest extends TestCase {

	public void testHeartbeat() throws Exception {
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
				"1234");
		Controller c2 = new Controller(cmd, "eth2", "255.255.255.0", "172.17.2.255", "172.17.2.1",
				addresses1,
				"127.0.0.2", "127.0.0.1",
				"1234");

		Thread t1 = new Thread(c1);
		t1.start();
		Thread t2 = new Thread(c2);
		t2.start();
		Thread.sleep(20000);

		System.out.println("start transfer");
		c1.setTransition(Transition.TRANSFER);
		Thread.sleep(20000);

		System.out.println("end controller 2");
		c2.end();
		Thread.sleep(20000);
				
		c1.end();
		System.out.println("end");
	}
}
