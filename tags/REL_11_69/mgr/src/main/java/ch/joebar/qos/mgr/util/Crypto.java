package ch.joebar.qos.mgr.util;

import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

/**
 * mod_qos, quality of service for web applications
 * 
 * See http://sourceforge.net/projects/mod-qos/ for further
 * details.
 *
 * Copyright (C) 2018 Pascal Buchbinder
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

public class Crypto {
	private static Logger log = Logger.getLogger(Crypto.class);

	private static int RANLEN = 10;

	/**
	 * Encypts the provided string.
	 * @param key Secret key which is used encryption/decryption
	 * @param value String to encrypt
	 * @return Encrypted and b64 encoded string or null on error
	 */
	public static String encrypt(SecretKey key, String value) {
        String enc = null;
        //SecureRandom srn = new SecureRandom();
        //byte[] bytes = srn.generateSeed(Controller.RANLEN);
        Random rand = new Random();
        long r = rand.nextLong();
        byte[] bytes = new Long(r).toString().getBytes();
        String rnd = new String(Base64.encodeBase64(bytes)).substring(0, Crypto.RANLEN);
        try {
        	Cipher cipher = Cipher.getInstance("DESede");
        	cipher.init(Cipher.ENCRYPT_MODE, key);
        	byte[] cipherText = cipher.doFinal(new String(rnd + value).getBytes());
        	enc = new String(Base64.encodeBase64(cipherText));
        } catch (Exception e) {
        	log.debug("could not encrypt value", e);
        }
        return enc;
	}

	/**
	 * Decrypts the provides string.
	 * 
	 * @param key Secret key which is used encryption/decryption
	 * @param value b64 encoded data to decrypt
	 * @return Decrypted string or null on error
	 */
	public static String decrypt(SecretKey key, String value) {
		String dec = null;
		try {
			byte[] cipherText = Base64.decodeBase64(value.getBytes());
			Cipher cipher = Cipher.getInstance("DESede");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decryptedMessage = cipher.doFinal(cipherText);
			String all = new String(decryptedMessage);
			if(all.length() > Crypto.RANLEN) {
				dec = all.substring(Crypto.RANLEN);
			}
		} catch (Exception e) {
			log.debug("could not decrypt value", e);
		}
		return dec;
	}
	
	/**
	 * 3DES key from passphrase.
	 * @param passphrase
	 * @return secret key or null on error
	 */
	public static SecretKey generateKey(String passphrase) {
		try {
			byte[] tripleDesKeyData = new String(passphrase + "ksjD700ndh_*%sbF4ky>s1hdnc").substring(0, 24).getBytes();
			return new SecretKeySpec(tripleDesKeyData, "DESede");
		} catch (Exception e) {
			log.error("could not create key: " + e.toString());
        }
		return null;
	}
}
