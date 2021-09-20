package ch.joebar.qos.mgr.util;

import java.io.IOException;

/** dummy class for command execution - DOES NOT REALLY WORK !!! */
public class CommandStarter {

	
	public CommandStarter(int sizeLimit, long timeout, long ioTimeout) {
	}
	
	public String callCommandToString(String[] cmdArray) {
		try {
			Runtime.getRuntime().exec(cmdArray);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}
}
