package ch.joebar.qos.mgr.test;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import ch.joebar.qos.mgr.conf.httpd.Httpd;

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
		pm.println("</VirtualHost>");
		out.close();
	}

	public void testMain() throws Exception {
		Httpd h = new Httpd(C);
		h.save(C+".bak");
	}

}
