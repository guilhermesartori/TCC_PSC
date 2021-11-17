package br.ufsc.tsp.service.utility;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import br.ufsc.labsec.valueobject.crypto.KNetRequester;
import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.labsec.valueobject.kmip.KkmipClientBuilder;

public class TestKeyManager {

	private KeyManager keyManager;

	@BeforeEach
	public void createKeyManager() throws KNetException {
		final Properties props = System.getProperties();
		props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("ADDRESS_CONN", "192.168.66.20");
		parameters.put("PORT_CONN", "60055");
		parameters.put("USERNAME", "test_user");
		parameters.put("PW", "2m;z#MkD-tcc-guilherme");
		parameters.put("MAX_CONNECTIONS", "1");

		KNetRequester kNetRequester = new KNetRequester(KkmipClientBuilder.build(null, null, parameters),
				parameters.get("USERNAME"), parameters.get("PW"));

		keyManager = new KeyManager(kNetRequester);
	}

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
