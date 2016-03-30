/*
 * Utilities for the quality of service module mod_qos.
 *
 * Log data signing tool to ensure data integrity.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2016 Pascal Buchbinder
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is released under the GPL with the additional
 * exemption that compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

package ch.joebar.qos.log.qssign;

import org.apache.log4j.RollingFileAppender;
import org.apache.log4j.helpers.LogLog;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;

/**
 * Modified version of the RollingFileAppender signing every
 * log message (sequence number and hmac).
 *
 * Property: "secret" species the shared secret used for the
 * hash creation / verification.
 *
 */
public class SigningFileAppender extends RollingFileAppender {

    protected String secret = null;
    
    public String getSecret() {
	return secret;
    }

    /**
     * Property defining the shared secret.
     *
     * @param value Shared secret (string).
     */
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
		Hmac h = new Hmac(secret, enc);
		retval = new SigningOutputStreamWriter(os, enc, h);
	    } catch(IOException e) {
		if (e instanceof InterruptedIOException) {
		    Thread.currentThread().interrupt();
		}
		LogLog.warn("Error initializing output writer.");
		LogLog.warn("Unsupported encoding?");
	    }
	}
	if(retval == null) {
	    Hmac h = new Hmac(secret);
	    retval = new SigningOutputStreamWriter(os, h);
	}
	return retval;
    }

}
