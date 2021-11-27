package br.ufsc.tsp.service;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;

import javax.transaction.Transactional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.domain.KeyPair;
import br.ufsc.tsp.exception.KeyPairServiceException;
import br.ufsc.tsp.exception.KeyPairServiceException.ExceptionType;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.KeyPairRepository;
import br.ufsc.tsp.service.utility.KeyManager;
import br.ufsc.tsp.service.utility.KeyParameterEncryptor;

@Service
@Transactional
public class KeyPairService {

	private final AppUserRepository appUserRepository;
	private final KeyPairRepository keyPairRepository;
	private final KeyManager keyManager;
	private final MessageDigest digest;
	private final KeyParameterEncryptor keyParameterEncryptor;

	/**
	 * 
	 * @param keyPairRepository
	 * @param appUserRepository
	 */
	@Autowired
	public KeyPairService(KeyPairRepository keyPairRepository, AppUserRepository appUserRepository,
			KeyManager keyManager, KeyParameterEncryptor keyParameterEncryptor) {
		super();
		this.keyPairRepository = keyPairRepository;
		this.appUserRepository = appUserRepository;
		this.keyManager = keyManager;
		this.keyParameterEncryptor = keyParameterEncryptor;
		try {
			this.digest = MessageDigest.getInstance("SHA-256", new BouncyCastleProvider());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public List<KeyPair> getKeyPairs() {
		return keyPairRepository.findAll();
	}

	public KeyPair createKeyPair(String username, String accessKey, String keyAlgorithm, String keyParameter,
			String keyName) throws KeyPairServiceException {
		try {
			if (keyPairRepository.existsKeyPairByKeyName(keyName))
				throw new KeyPairServiceException(ExceptionType.KEY_NAME_IN_USE);

			var identifiers = keyManager.createKeyPair(keyAlgorithm, keyParameter, keyName);

			var privateKeyIdentifier = identifiers.getPrivateKeyIdentifier();
			var publicKeyIdentifier = identifiers.getPublicKeyIdentifier();
			var uniqueIdentifier = generateUniqueIdentifier(privateKeyIdentifier, publicKeyIdentifier);
			var keyOwner = appUserRepository.findAppUserByUsername(username);

			var encryptedPrivateKeyIdentifier = keyParameterEncryptor.encrypt(privateKeyIdentifier, accessKey);

			var keyPairEntity = new KeyPair(publicKeyIdentifier, encryptedPrivateKeyIdentifier, keyAlgorithm,
					uniqueIdentifier, keyName, keyOwner);

			return keyPairRepository.save(keyPairEntity);
		} catch (NoSuchAlgorithmException | KNetException e) {
			throw new KeyPairServiceException();
		}
	}

	public void deleteKeyPair(String username, String encodingKey, String uniqueIdentifier)
			throws KNetException, KeyPairServiceException {
		var user = appUserRepository.findAppUserByUsername(username);
		var optionalkeyPair = keyPairRepository.findKeyPairByOwnerAndUniqueIdentifier(user, uniqueIdentifier);
		if (optionalkeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		else {
			var keyPair = optionalkeyPair.get();
			var privateKeyIdentifier = keyParameterEncryptor.decrypt(keyPair.getPrivateKey(), encodingKey);
			keyManager.deleteKeyPair(privateKeyIdentifier, keyPair.getPublicKey());
			keyPairRepository.deleteKeyPairByUniqueIdentifier(uniqueIdentifier);
		}
	}

	public String sign(String username, String accessKey, String base64EncodedData, String keyUniqueIdentifier,
			String hashingAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
			KNetException, KeyPairServiceException {
		var user = appUserRepository.findAppUserByUsername(username);
		var optionalkeyPair = keyPairRepository.findKeyPairByOwnerAndUniqueIdentifier(user, keyUniqueIdentifier);
		if (optionalkeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);

		var base64Decoder = Base64.getDecoder();
		var data = base64Decoder.decode(base64EncodedData);

		var hashedData = MessageDigest.getInstance(hashingAlgorithm, new BouncyCastleProvider()).digest(data);

		var keyPair = optionalkeyPair.get();
		var privateKeyIdentifier = keyParameterEncryptor.decrypt(keyPair.getPrivateKey(), accessKey);
		var signature = keyManager.sign(privateKeyIdentifier, keyPair.getKeyAlgorithm(), hashedData);
		var base64Encoder = Base64.getEncoder();
		var base64Signature = base64Encoder.encodeToString(signature);

		return base64Signature;
	}

	private String generateUniqueIdentifier(String privateKeyIdentifier, String publicKeyIdentifier)
			throws NoSuchAlgorithmException {
		var base64Encoder = Base64.getEncoder();

		var encodedPrivateKey = privateKeyIdentifier.getBytes();
		var encodedPublicKey = publicKeyIdentifier.getBytes();

		var base64EncodedPrivateKey = base64Encoder.encodeToString(encodedPrivateKey);
		var base64EncodedPublicKey = base64Encoder.encodeToString(encodedPublicKey);

		var publicAndPrivateKeyConcatenation = base64EncodedPublicKey + base64EncodedPrivateKey;
		var digested = digest.digest(publicAndPrivateKeyConcatenation.getBytes());
		var uniqueIdentifierBytes = Arrays.copyOf(digested, 64);
		var uniqueIdentifier = base64Encoder.encodeToString(uniqueIdentifierBytes);

		return uniqueIdentifier;
	}

}
