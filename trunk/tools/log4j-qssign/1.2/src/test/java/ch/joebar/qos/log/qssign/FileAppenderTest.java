package ch.joebar.qos.log.qssign;

import java.io.File;
import java.io.IOException;
import org.apache.log4j.Logger;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Simple test generation some log data....
 */
public class FileAppenderTest extends TestCase {
    static Logger log = Logger.getLogger(FileAppenderTest.class.getName());

    static private File logFile;

    public FileAppenderTest(String testName) {
	super( testName );
	String path = System.getProperty("user.dir") + File.separator + "signed.log";
	logFile = new File(path);
	log.error("create test message");
    }

    public static Test suite() {
        return new TestSuite(FileAppenderTest.class);
    }

    public void testApp() throws InterruptedException {
	for(int i = 0; i < 10000; i+=10) {
	    Thread.sleep(2);
	    log.info("run test message " + i);
	}
	IOException e = new IOException("IO error");
	log.error("exception test message incl. stack trace", e);
    }
}
