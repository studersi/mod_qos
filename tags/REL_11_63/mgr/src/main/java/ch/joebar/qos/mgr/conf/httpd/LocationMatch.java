package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;

public class LocationMatch extends Location {

	LocationMatch(BufferedReader br, Line line) throws IOException {
		super(br, line);
	}

	protected boolean end(Line line) {
		return line.isLocationMatchEnd();
	}
	
	protected String tag() {
		return "LocationMatch";
	}
}
