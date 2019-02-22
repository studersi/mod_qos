/*
 * Utilities for the quality of service module mod_qos.
 *
 * SigningOutputStreamWriter.java: Log data signing tool to
 * ensure data integrity.
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2019 Pascal Buchbinder
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
