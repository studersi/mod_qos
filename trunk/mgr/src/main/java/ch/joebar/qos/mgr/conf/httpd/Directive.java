package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;

public class Directive extends Entry {

	Directive(BufferedReader br, Line line) throws IOException {
		super(null, line);
	}


}
