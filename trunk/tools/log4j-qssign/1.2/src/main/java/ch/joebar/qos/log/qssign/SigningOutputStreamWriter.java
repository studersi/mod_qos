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

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.OutputStream;

/**
 * Modified OutputStreamWriter signing log messages.
 */
public class SigningOutputStreamWriter extends OutputStreamWriter {

    private long sequence = 1;
    private Hmac hmac;

    public SigningOutputStreamWriter(OutputStream out, String enc, Hmac h) throws IOException {
	super(out, enc);
	hmac = h;
    }

    public SigningOutputStreamWriter(OutputStream out, Hmac h) {
	super(out);
	hmac = h;
    }

    /**
     * Signs every log message by appending a sequence number and then
     * hashing the line.
     * Ignores ignoresThrowable() (also signs stack traces).
     *
     * @param value Line which shall be signed and written to the log.
     */
    @Override
    public void write(String value) throws IOException {
	String numberedLine = String.format("%s %012d", value.trim(), sequence);
	String mac = hmac.getMac(numberedLine);
	String signedLine = String.format("%s#%s%n", numberedLine, mac);
	sequence++;
	super.write(signedLine);
    }

}
