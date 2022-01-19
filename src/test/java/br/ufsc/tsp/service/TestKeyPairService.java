package br.ufsc.tsp.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.repository.KeyPairRepository;
import br.ufsc.tsp.service.exception.AppUserServiceException;
import br.ufsc.tsp.service.exception.KeyManagerException;
import br.ufsc.tsp.service.exception.KeyPairServiceException;
import br.ufsc.tsp.service.exception.SystemServiceException;

@SpringBootTest
public class TestKeyPairService {

	private static final String USER_USERNAME = "test";
	private static final String USER_PASSWORD = "test";

	@Autowired
	private KeyPairService keyPairService;

	@Autowired
	private AppUserService appUserService;

	@Autowired
	private KeyParameterEncryptor keyParameterEncryptor;

	@Autowired
	private KeyPairRepository keyPairRepository;

	@Autowired
	private KNetCommunicationService keyManager;

	@Autowired
	private SystemConfigurationService systemConfigurationService;

	private String accessKey;

	@BeforeEach
	public void runBeforeEach() throws KNetException, SystemServiceException {
		var authorities = new ArrayList<Authority>();
		authorities.add(Authority.USER);
		appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);
		accessKey = keyParameterEncryptor.encryptKey(USER_PASSWORD);
		var parameters = new HashMap<String, String>();
		parameters.put("ADDRESS_CONN", "192.168.66.20");
		parameters.put("PORT_CONN", "60055");
		parameters.put("USERNAME", "test_user");
		parameters.put("PW", "2m;z#MkD-tcc-guilherme");
		parameters.put("MAX_CONNECTIONS", "1");
		systemConfigurationService.setKnetConfiguration(parameters, accessKey);
	}

	@AfterEach
	public void runAfterEach() throws AppUserServiceException {
		appUserService.deleteUserByUsername(USER_USERNAME);
	}

	@Test
	public void test_createKeyPair_RSA_2048() throws KeyPairServiceException, KNetException, KeyManagerException {
		final var algorithm = "RSA";
		final var parameter = "2048";
		final var keyName = "test_createKeyPair_RSA_2048";

		var keyPair = keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, keyName);

		keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

		assertEquals(keyPair.getKeyAlgorithm(), algorithm);
		assertEquals(keyPair.getOwner().getUsername(), USER_USERNAME);
		assertNotNull(keyPair.getPrivateKey());
		assertNotNull(keyPair.getPublicKey());
		assertNotNull(keyPair.getUniqueIdentifier());
		assertNotNull(keyPair.getId());
	}

	@Test
	public void test_sign_RSA_2048_SHA256() throws KeyPairServiceException, KNetException, InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, KeyManagerException {
		final var algorithm = "RSA";
		final var parameter = "2048";
		final var keyName = "test_sign_RSA_2048_SHA256";
		final var hashingAlgorithm = "SHA256";
		final var dataToSign = "test".getBytes();
		final var base64EncodedDataToSign = Base64.getEncoder().encodeToString(dataToSign);
		final var keyPair = keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, keyName);
		final var publicKey = keyManager.getPublicKey(keyPair.getPublicKey(), algorithm);
		final var signature = Signature.getInstance("SHA256WithRSA", new BouncyCastleProvider());
		signature.initVerify(publicKey);
		signature.update(dataToSign);

		var signedData = keyPairService.sign(USER_USERNAME, accessKey, base64EncodedDataToSign,
				keyPair.getUniqueIdentifier(), hashingAlgorithm);

		keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

		assertTrue(signature.verify(Base64.getDecoder().decode(signedData)));
	}

	@Test
	public void deleteKeyPair_RSA_2048() throws KeyPairServiceException, KNetException, KeyManagerException {
		final var algorithm = "RSA";
		final var parameter = "2048";
		final var keyName = "deleteKeyPair_RSA_2048";
		var keyPair = keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, keyName);

		keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

		assertFalse(keyPairRepository.existsKeyPairByUniqueIdentifier(keyPair.getUniqueIdentifier()));

	}

}
