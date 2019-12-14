package ch.joebar.qos.mgr.test;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Iterator;

import ch.joebar.qos.mgr.conf.httpd.Httpd;
import ch.joebar.qos.mgr.conf.httpd.Locations;
import ch.joebar.qos.mgr.conf.httpd.VirtualHost;
import ch.joebar.qos.mgr.conf.httpd.VirtualHosts;

import junit.framework.TestCase;

public class ConfTest extends TestCase {
	
	static String C = "./src/test/conf/httpd.conf";

	public void setUp() throws Exception {
		OutputStream out = new FileOutputStream(C);
		PrintStream pm = new PrintStream(out);
		pm.println("# comment");
		pm.println("ServerLimit 1");
		pm.println("<VirtualHost server:80>");
		pm.println("  ServerName server");
		pm.println("  <Location /main>");
		pm.println("    SetHandler server-status");
		pm.println("  </location>");
		pm.println("");
		pm.println("  <Location \"/main/sub\">");
		pm.println("    QS_DenyQuery       +s01       deny \"(EXEC|SELECT|INSERT|UPDATE|DELETE)\"");
		pm.println("    QS_DenyQuery       +s02       deny \"(DROP)\"");
		pm.println("  </Location>");
		pm.println("");
		pm.println("");
		pm.println("");
		pm.println("");
		pm.println("</VirtualHost>");
		out.close();
	}

	public void testMain() throws Exception {
		Httpd h = new Httpd(C);
		VirtualHosts vs = h.getVirtualHosts();
		System.out.println("hosts: " + vs.size());
		if(vs.size() != 1) {
			super.fail();
		}

		Iterator<String> it = vs.keySet().iterator();
		VirtualHost v = vs.get(it.next());
		if(v == null) {
			super.fail();
		}
		Locations ls = v.getLocations();
		System.out.println("locations: " + ls.size());
		if(ls.size() != 2) {
			super.fail();
		}

		h.save(C+".bak");
	}

}
