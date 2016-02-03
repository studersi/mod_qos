package ch.joebar.qos.log.qssign;

import org.apache.log4j.RollingFileAppender;
import org.apache.log4j.helpers.LogLog;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;

public class SigningFileAppender extends RollingFileAppender {

    protected String secret = null;
    
    public String getSecret() {
	return secret;
    }

    public void setSecret(String value) {
	secret = value;
    }

    @Override
    protected OutputStreamWriter createWriter(OutputStream os) {
	OutputStreamWriter retval = null;
	
	if(secret == null) {
	    LogLog.warn("Missing property [secret] for " + SigningFileAppender.class.getName());
	}

	String enc = getEncoding();
	if(enc != null) {
	    try {
		retval = new SigningOutputStreamWriter(os, enc);
	    } catch(IOException e) {
		if (e instanceof InterruptedIOException) {
		    Thread.currentThread().interrupt();
		}
		LogLog.warn("Error initializing output writer.");
		LogLog.warn("Unsupported encoding?");
	    }
	}
	if(retval == null) {
	    retval = new OutputStreamWriter(os);
	}
	return retval;
    }

    //@Override
    //protected void closeFile() {
    //	if(this.qw != null) {
    //	    this.qw.write("END");
    //	}
    //}

}
