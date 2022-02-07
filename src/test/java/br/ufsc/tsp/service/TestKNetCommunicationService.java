package br.ufsc.tsp.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.service.exception.KNetCommunicationServiceException;
import br.ufsc.tsp.service.exception.SystemServiceException;

@SpringBootTest
public class TestKNetCommunicationService {

	@Autowired
	private KNetCommunicationService knetCommunicationService;

	@Autowired
	private SystemConfigurationService systemConfigurationService;

	@Autowired
	private ParameterEncryptor parameterEncryptor;

	private static Map<String, String> knetParameters;

	static {
		knetParameters = new HashMap<String, String>();
		knetParameters.put("ADDRESS_CONN", "192.168.66.20");
		knetParameters.put("PORT_CONN", "60055");
		knetParameters.put("USERNAME", "test_user");
		knetParameters.put("PW", "2m;z#MkD-tcc-guilherme");
		knetParameters.put("MAX_CONNECTIONS", "1");
	}

	private void createKnetConfiguration() throws KNetException {
		knetCommunicationService.setKnetConfiguration(knetParameters);
	}

	@Test
	public void createKeyPair_success() throws KNetException, KNetCommunicationServiceException {
		createKnetConfiguration();

		final var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");

		knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
				identifiers.getPublicKeyIdentifier());
		assertNotNull(identifiers.getPrivateKeyIdentifier());
		assertNotNull(identifiers.getPublicKeyIdentifier());

	}

	@Test
	public void createKeyPair_fail() throws KNetException, KNetCommunicationServiceException {
		knetCommunicationService.setkNetRequester(null);

		assertThrows(KNetCommunicationServiceException.class, () -> {
			final var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");

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
			final var data = MessageDigest.getInstance("SHA256").digest("test".getBytes());

			final var signature = knetCommunicationService.sign(identifiers.getPrivateKeyIdentifier(), "RSA", data);
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
		final var data = MessageDigest.getInstance("SHA256").digest("test".getBytes());

		assertThrows(KNetCommunicationServiceException.class, () -> {
			knetCommunicationService.sign("test", "RSA", data);
		});
	}

	@Test
	public void deleteKeyPair_success() throws KNetException, KNetCommunicationServiceException {
		createKnetConfiguration();
		final var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");

		assertDoesNotThrow(() -> {
			knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
					identifiers.getPublicKeyIdentifier());
		});
	}

	@Test
	public void deleteKeyPair_fail() throws KNetException, KNetCommunicationServiceException {
		createKnetConfiguration();
		final var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");
		knetCommunicationService.setkNetRequester(null);

		assertThrows(KNetCommunicationServiceException.class, () -> {
			knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
					identifiers.getPublicKeyIdentifier());
		});

		createKnetConfiguration();
		knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
				identifiers.getPublicKeyIdentifier());
	}

	@Test
	public void getPublicKey_success() throws KNetException, KNetCommunicationServiceException {
		createKnetConfiguration();
		final var identifiers = knetCommunicationService.createKeyPair("RSA", "1024", "test_createKeyPair");

		final var publicKey = knetCommunicationService.getPublicKey(identifiers.getPublicKeyIdentifier(), "RSA");

		assertNotNull(publicKey);

		knetCommunicationService.deleteKeyPair(identifiers.getPrivateKeyIdentifier(),
				identifiers.getPublicKeyIdentifier());
	}

	@Test
	public void getPublicKey_fail() throws KNetException, KNetCommunicationServiceException {
		knetCommunicationService.setkNetRequester(null);

		assertThrows(KNetCommunicationServiceException.class, () -> {
			knetCommunicationService.getPublicKey("test", "RSA");
		});
	}

	@Test
	public void isKnetConfigurationLoaded_true() throws KNetException, KNetCommunicationServiceException {
		createKnetConfiguration();

		final var isLoaded = knetCommunicationService.isKnetConfigurationLoaded();

		assertTrue(isLoaded);
	}

	@Test
	public void isKnetConfigurationLoaded_false() throws KNetException, KNetCommunicationServiceException {
		knetCommunicationService.setkNetRequester(null);

		final var isLoaded = knetCommunicationService.isKnetConfigurationLoaded();

		assertFalse(isLoaded);

	}

	@Test
	public void loadKnetConfiguration_success()
			throws KNetException, KNetCommunicationServiceException, SystemServiceException {
		final var accessKey = parameterEncryptor.encryptKey("test");
		final var savedKnetConfiguration = systemConfigurationService.setKnetConfiguration(knetParameters, accessKey);

		assertDoesNotThrow(() -> {
			knetCommunicationService.loadKnetConfiguration(accessKey);

		});

		systemConfigurationService.deleteKnetConfiguration(savedKnetConfiguration);
	}

	@Test
	public void loadKnetConfiguration_fail_noConfiguration() throws KNetException {
		final var accessKey = parameterEncryptor.encryptKey("test");

		assertThrows(KNetCommunicationServiceException.class, () -> {
			knetCommunicationService.loadKnetConfiguration(accessKey);

		});

	}

}
