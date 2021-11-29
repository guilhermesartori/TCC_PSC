package br.ufsc.tsp.service.utility;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.exception.KNetException;

@SpringBootTest
public class TestKeyManager {

	@Autowired
	private KeyManager keyManager;

	@Test
	public void test_createKeyPair() throws KNetException {
		var identifiers = keyManager.createKeyPair("RSA", "1024", "test_createKeyPair");

		keyManager.deleteKeyPair(identifiers.getPrivateKeyIdentifier(), identifiers.getPublicKeyIdentifier());
		assertNotNull(identifiers.getPrivateKeyIdentifier());
		assertNotNull(identifiers.getPublicKeyIdentifier());

	}

	@Test
	public void test_sign() throws KNetException, NoSuchAlgorithmException {
		KeyIdentifierPair identifiers = null;
		try {
			identifiers = keyManager.createKeyPair("RSA", "1024", "test_sign");
			var data = MessageDigest.getInstance("SHA256").digest("test".getBytes());

			var signature = keyManager.sign(identifiers.getPrivateKeyIdentifier(), "RSA", data);
			assertNotNull(signature);
		} catch (Exception e) {
			fail();
		} finally {
			if (identifiers != null)
				keyManager.deleteKeyPair(identifiers.getPrivateKeyIdentifier(), identifiers.getPublicKeyIdentifier());
		}
	}
}
