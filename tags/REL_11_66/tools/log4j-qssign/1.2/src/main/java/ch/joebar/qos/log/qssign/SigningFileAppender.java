/*
 * Utilities for the quality of service module mod_qos.
 *
 * SigningFileAppender.java: Log data signing tool to ensure
 * data integrity.
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2020 Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
