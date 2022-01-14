package br.ufsc.tsp.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class TestKeyParameterEncryptor {

	@Autowired
	private KeyParameterEncryptor keyParameterEncryptor;
	private String encryptedKey;
	private String valueToBeEncrypted;

	@BeforeEach
	public void initialize() {
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
