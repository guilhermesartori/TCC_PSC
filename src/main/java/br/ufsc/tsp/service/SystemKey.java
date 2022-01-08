package br.ufsc.tsp.service;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;

public class SystemKey {

	public static final String SYSTEM_KEY_ALGORITHM = "AES";

	private static byte[] KEY;
	private static KeyGenerator keyGenerator;

	static {
		try {
			keyGenerator = KeyGenerator.getInstance(SYSTEM_KEY_ALGORITHM);
			keyGenerator.init(256);
		} catch (NoSuchAlgorithmException e) {
			// should never happen
		}
	}

	public static byte[] getKey() {
		if (KEY == null)
			KEY = keyGenerator.generateKey().getEncoded();
		return KEY;
	}

	public static void refreshKey() {
		KEY = keyGenerator.generateKey().getEncoded();
	}

}
