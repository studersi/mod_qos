/*
 * Utilities for the quality of service module mod_qos.
 *
 * Hmac.java: Log data signing tool to ensure data integrity.
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

import org.apache.log4j.helpers.LogLog;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

public class Hmac {

    private static final String HMAC_SHA = "HmacSHA1";
    private Mac mac;
    private String encoding = "UTF-8";

    public Hmac(String secret, String enc) {
	init(secret);
	encoding = enc;
    }

    public Hmac(String secret) {
	init(secret);
    }

    private void init(String secret) {
	if(secret != null) {
	    byte[] b = secret.getBytes();
	    SecretKeySpec keySpec = new SecretKeySpec(b, HMAC_SHA);
	    try {
		mac = Mac.getInstance(HMAC_SHA);
		mac.init(keySpec);
	    } catch (Exception e) {
		LogLog.error("Unexpected error initializing mac", e);
	    }
	} else {
	    LogLog.error("Missing secret. Can't initialize secret key.");
	}
    }

    public String getMac(String value) {
	String hash = "ERR";
	if(mac == null) {
	    return hash;
	}
	try {
	    byte[] b = value.getBytes(encoding);
	    byte[] result = mac.doFinal(b);
	    byte[] encodedBytes = Base64.encodeBase64(result);
	    hash = new String(encodedBytes);
	} catch (Exception e) {
	    LogLog.warn("Unexpected error while hashing log line", e);
	}
	return hash;
    }
}
