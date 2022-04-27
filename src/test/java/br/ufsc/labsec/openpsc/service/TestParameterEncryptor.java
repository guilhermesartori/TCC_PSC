package br.ufsc.labsec.openpsc.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.labsec.openpsc.service.ParameterEncryptor;

@SpringBootTest
public class TestParameterEncryptor {

	@Autowired
	private ParameterEncryptor parameterEncryptor;
	private String encryptedKey;
	private String valueToBeEncrypted;

	@BeforeEach
	public void initialize() {
		encryptedKey = parameterEncryptor.encryptKey("password");
		valueToBeEncrypted = "test";
	}

	@Test
	public void test_encrypt() {
		String encryption = parameterEncryptor.encrypt(valueToBeEncrypted, encryptedKey);
		assertNotNull(encryption);
	}

	@Test
	public void test_decrypt() {
		String encryption = parameterEncryptor.encrypt(valueToBeEncrypted, encryptedKey);

		String decryption = parameterEncryptor.decrypt(encryption, encryptedKey);
		assertNotNull(decryption);
		assertEquals(valueToBeEncrypted, decryption);
	}

}
