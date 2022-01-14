package br.ufsc.tsp.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.service.exception.KeyManagerException;

@SpringBootTest
public class TestKeyManager {

	@Autowired
	private KNetCommunicationService keyManager;

	@BeforeEach
	private void createKnetConfiguration() throws KNetException {
		var parameters = new HashMap<String, String>();
		parameters.put("ADDRESS_CONN", "192.168.66.20");
		parameters.put("PORT_CONN", "60055");
		parameters.put("USERNAME", "test_user");
		parameters.put("PW", "2m;z#MkD-tcc-guilherme");
		parameters.put("MAX_CONNECTIONS", "1");
		keyManager.setKnetConfiguration(parameters);
	}

	@Test
	public void test_createKeyPair() throws KNetException, KeyManagerException {
		var identifiers = keyManager.createKeyPair("RSA", "1024", "test_createKeyPair");

		keyManager.deleteKeyPair(identifiers.getPrivateKeyIdentifier(), identifiers.getPublicKeyIdentifier());
		assertNotNull(identifiers.getPrivateKeyIdentifier());
		assertNotNull(identifiers.getPublicKeyIdentifier());

	}

	@Test
	public void test_sign() throws KNetException, NoSuchAlgorithmException, KeyManagerException {
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
