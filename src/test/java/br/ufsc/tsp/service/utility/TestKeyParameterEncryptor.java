package br.ufsc.tsp.service.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TestKeyParameterEncryptor {

	private KeyParameterEncryptor keyParameterEncryptor;
	private String encryptedKey;
	private String valueToBeEncrypted;

	@BeforeEach
	public void initialize() {
		keyParameterEncryptor = new KeyParameterEncryptor();
		encryptedKey = keyParameterEncryptor.encryptKey("password");
		valueToBeEncrypted = "test";
	}

	@Test
	public void test_encrypt() {
		String encryption = keyParameterEncryptor.encrypt(valueToBeEncrypted, encryptedKey);
		assertNotNull(encryption);
	}

	@Test
	public void test_decrypt() {
		String encryption = keyParameterEncryptor.encrypt(valueToBeEncrypted, encryptedKey);

		String decryption = keyParameterEncryptor.decrypt(encryption, encryptedKey);
		assertNotNull(decryption);
		assertEquals(valueToBeEncrypted, decryption);
	}

}
