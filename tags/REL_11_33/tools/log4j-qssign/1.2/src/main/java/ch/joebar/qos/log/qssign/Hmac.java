/*
 * Utilities for the quality of service module mod_qos.
 *
 * Log data signing tool to ensure data integrity.
 *
 * See http://mod-qos.sourceforge.net/ for further
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
