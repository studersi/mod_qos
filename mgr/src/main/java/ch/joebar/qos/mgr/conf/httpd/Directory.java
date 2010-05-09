package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;

public class Directory extends Location {

	Directory(BufferedReader br, Line line) throws IOException {
		super(br, line);
	}

	protected boolean end(Line line) {
		return line.isDirectoryEnd();
	}
	
	protected String tag() {
		return "Directory";
	}

}
