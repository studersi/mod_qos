
package ch.joebar.qos.mgr;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.log4j.Logger;

public class Listener implements ServletContextListener {
	private static Logger log = Logger.getLogger(Listener.class);
		
	public void contextDestroyed(ServletContextEvent arg0) {
	}

	public void contextInitialized(ServletContextEvent arg0) {
	}

}
