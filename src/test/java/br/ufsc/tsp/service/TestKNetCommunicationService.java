package br.ufsc.tsp.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.service.exception.KNetCommunicationServiceException;

@SpringBootTest
public class TestKNetCommunicationService {

	@Autowired
	private KNetCommunicationService knetCommunicationService;

	private void createKnetConfiguration() throws KNetException {
		var parameters = new HashMap<String, String>();
		parameters.put("ADDRESS_CONN", "192.168.66.20");
		parameters.put("PORT_CONN", "60055");
		parameters.put("USERNAME", "test_user");
		parameters.put("PW", "2m;z#MkD-tcc-guilherme");
		parameters.put("MAX_CONNECTIONS", "1");
		knetCommunicationService.setKnetConfiguration(parameters);
	}

	@Test
	public void createKeyPair_success() throws KNetException, KNetCommunicationServiceException {
		createKnetConfiguration();

		var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");

		knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
				identifiers.getPublicKeyIdentifier());
		assertNotNull(identifiers.getPrivateKeyIdentifier());
		assertNotNull(identifiers.getPublicKeyIdentifier());

	}

	@Test
	public void createKeyPair_fail() throws KNetException, KNetCommunicationServiceException {
		knetCommunicationService.setkNetRequester(null);

		assertThrows(KNetCommunicationServiceException.class, () -> {
			var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");

			knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
					identifiers.getPublicKeyIdentifier());
		});
	}

	@Test
	public void sign_success() throws KNetException, NoSuchAlgorithmException, KNetCommunicationServiceException {
		createKnetConfiguration();

		KeyIdentifierPair identifiers = null;
		try {
			identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_sign");
			var data = MessageDigest.getInstance("SHA256").digest("test".getBytes());

			var signature = knetCommunicationService.sign(identifiers.getPrivateKeyIdentifier(), "RSA", data);
			assertNotNull(signature);
		} catch (Exception e) {
			fail();
		} finally {
			if (identifiers != null)
				knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
						identifiers.getPublicKeyIdentifier());
		}
	}

	@Test
	public void sign_fail() throws KNetException, NoSuchAlgorithmException, KNetCommunicationServiceException {
		knetCommunicationService.setkNetRequester(null);
		var data = MessageDigest.getInstance("SHA256").digest("test".getBytes());

		assertThrows(KNetCommunicationServiceException.class, () -> {
			knetCommunicationService.sign("test", "RSA", data);
		});
	}

	@Test
	public void deleteKeyPair_success() throws KNetException, KNetCommunicationServiceException {
		createKnetConfiguration();
		var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");

		assertDoesNotThrow(() -> {
			knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
					identifiers.getPublicKeyIdentifier());
		});
	}

	@Test
	public void deleteKeyPair_fail() throws KNetException, KNetCommunicationServiceException {
		createKnetConfiguration();
		var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");
		knetCommunicationService.setkNetRequester(null);

		assertThrows(KNetCommunicationServiceException.class, () -> {
			knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
					identifiers.getPublicKeyIdentifier());
		});
		
		createKnetConfiguration();
		knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
				identifiers.getPublicKeyIdentifier());
	}

}
