package ch.joebar.qos.mgr.conf.httpd;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a single line of the configuration file.
 * @author pbu
 *
 */
public class Line {

	protected String line;
	
	/**
	 * Reads a line.
	 * @param br to read the line from
	 * @throws IOException on end of file
	 */
	Line(BufferedReader br) throws IOException {
		if(br != null) {
			String line = br.readLine();
			if(line == null) {
				throw new IOException();
			}
			while(line.endsWith("\\")) {
				String next = br.readLine();
				if(next != null) {
					line = line.substring(0, line.length()-1) + next;
				}
			}
			this.line = line.replace("\t", " ").trim();
		}
	}
	
	/**
	 * Raw line (trimmed)
	 * @return
	 */
	public String get() {
		return this.line;
	}
	
	public boolean isComment() {
		if(this.line.startsWith("#")) {
			return true;
		}
		return false;
	}
	
	public boolean isEmpty() {
		if(line.length() == 0) {
			return true;
		}
		return false;
	}

	public boolean isDirective() {
		return !this.isComment() &&
				!this.isEmpty() &&
				!this.isVirtualHost() &&
				!this.isLocation() &&
				!this.isLocationMatch() &&
				!this.isDirectory();
	}
	
	public boolean isVirtualHost() {
		Pattern p = Pattern.compile("^<[ \t]*VirtualHost[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isVirtualHostEnd() {
		Pattern p = Pattern.compile("^<[ \t]*/[ \t]*VirtualHost[ \t]*>.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}	
	
	public boolean isLocation() {
		Pattern p = Pattern.compile("^<[ \t]*Location[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isLocationEnd() {
		Pattern p = Pattern.compile("^<[ \t]*/[ \t]*Location[ \t]*>.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isLocationMatch() {
		Pattern p = Pattern.compile("^<[ \t]*LocationMatch[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isLocationMatchEnd() {
		Pattern p = Pattern.compile("^<[ \t]*/[ \t]*LocationMatch[ \t]*>.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isDirectory() {
		Pattern p = Pattern.compile("^<[ \t]*Directory[ \t]+.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}

	public boolean isDirectoryEnd() {
		Pattern p = Pattern.compile("^<[ \t]*/[ \t]*Directory[ \t]*>.*", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(this.line);
		return m.matches();
	}
}
