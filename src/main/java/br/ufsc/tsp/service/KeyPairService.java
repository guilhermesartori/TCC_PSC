package br.ufsc.tsp.service;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;

import javax.transaction.Transactional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.entity.KeyPair;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.KeyPairRepository;
import br.ufsc.tsp.service.exception.KNetCommunicationServiceException;
import br.ufsc.tsp.service.exception.KeyPairServiceException;
import br.ufsc.tsp.service.exception.KeyPairServiceException.ExceptionType;

@Service
@Transactional
public class KeyPairService {

	private final AppUserRepository appUserRepository;
	private final KeyPairRepository keyPairRepository;
	private final KNetCommunicationService keyManager;
	private final MessageDigest digest;
	private final ParameterEncryptor parameterEncryptor;

	/**
	 * 
	 * @param keyPairRepository
	 * @param appUserRepository
	 */
	@Autowired
	public KeyPairService(KeyPairRepository keyPairRepository, AppUserRepository appUserRepository,
			KNetCommunicationService keyManager, ParameterEncryptor parameterEncryptor) {
		super();
		this.keyPairRepository = keyPairRepository;
		this.appUserRepository = appUserRepository;
		this.keyManager = keyManager;
		this.parameterEncryptor = parameterEncryptor;
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
			String keyName) throws KeyPairServiceException, KNetCommunicationServiceException {
		try {
			if (keyPairRepository.existsKeyPairByKeyName(keyName))
				throw new KeyPairServiceException(ExceptionType.KEY_NAME_IN_USE);

			var identifiers = keyManager.createKeyPair(keyAlgorithm, keyParameter, keyName);

			var privateKeyIdentifier = identifiers.getPrivateKeyIdentifier();
			var publicKeyIdentifier = identifiers.getPublicKeyIdentifier();
			var uniqueIdentifier = generateUniqueIdentifier(privateKeyIdentifier, publicKeyIdentifier);
			var keyOwner = appUserRepository.findAppUserByUsername(username).get();

			var encryptedPrivateKeyIdentifier = parameterEncryptor.encrypt(privateKeyIdentifier, accessKey);

			var keyPairEntity = new KeyPair(publicKeyIdentifier, encryptedPrivateKeyIdentifier, keyAlgorithm,
					uniqueIdentifier, keyName, keyOwner);

			return keyPairRepository.save(keyPairEntity);
		} catch (NoSuchAlgorithmException | KNetException | IllegalArgumentException e) {
			throw new KeyPairServiceException();
		}
	}

	public void deleteKeyPair(String username, String encodingKey, String uniqueIdentifier)
			throws KNetException, KeyPairServiceException, KNetCommunicationServiceException {
		var optionalKeyPair = keyPairRepository.findKeyPairByOwnerUsernameAndUniqueIdentifier(username,
				uniqueIdentifier);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		else {
			var keyPair = optionalKeyPair.get();
			var privateKeyIdentifier = parameterEncryptor.decrypt(keyPair.getPrivateKey(), encodingKey);
			keyManager.deleteKeyPair(privateKeyIdentifier, keyPair.getPublicKey());
			keyPairRepository.deleteKeyPairByUniqueIdentifier(uniqueIdentifier);
		}
	}

	public String sign(String username, String accessKey, String base64EncodedData, String keyUniqueIdentifier,
			String hashingAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
			KNetException, KeyPairServiceException, KNetCommunicationServiceException {
		var optionalKeyPair = keyPairRepository.findKeyPairByOwnerUsernameAndUniqueIdentifier(username,
				keyUniqueIdentifier);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);

		var base64Decoder = Base64.getDecoder();
		var data = base64Decoder.decode(base64EncodedData);

		var hashedData = MessageDigest.getInstance(hashingAlgorithm, new BouncyCastleProvider()).digest(data);

		var keyPair = optionalKeyPair.get();
		var privateKeyIdentifier = parameterEncryptor.decrypt(keyPair.getPrivateKey(), accessKey);
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

	public KeyPair getKeyPair(String username, String keyUniqueIdentifier) throws KeyPairServiceException {
		var optionalKeyPair = keyPairRepository.findKeyPairByOwnerUsernameAndUniqueIdentifier(username,
				keyUniqueIdentifier);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		return optionalKeyPair.get();
	}

	public boolean verifySignature(String keyUniqueIdentifier, String base64EncodedData, String base64EncodedSignature,
			String signatureAlgorithm) throws KeyPairServiceException, KNetException, KNetCommunicationServiceException,
			InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		var optionalKeyPair = keyPairRepository.findKeyPairByUniqueIdentifier(keyUniqueIdentifier);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);

		var keyPair = optionalKeyPair.get();
		var algorithm = keyPair.getKeyAlgorithm();
		var publicKeyIdentifier = keyPair.getPublicKey();
		var publicKey = keyManager.getPublicKey(publicKeyIdentifier, algorithm);

		var data = Base64.getDecoder().decode(base64EncodedData);
		var signature = Base64.getDecoder().decode(base64EncodedSignature);

		var signatureVerifier = Signature.getInstance(signatureAlgorithm, new BouncyCastleProvider());
		signatureVerifier.initVerify(publicKey);
		signatureVerifier.update(data);
		return signatureVerifier.verify(signature);
	}

	public String getPublicKey(String keyIdentifier, String keyAlgorithm) throws KeyPairServiceException {
		try {
			var publicKey = keyManager.getPublicKey(keyIdentifier, keyAlgorithm);
			var encodedPublicKey = publicKey.getEncoded();
			var base64Encoding = Base64.getEncoder().encodeToString(encodedPublicKey);
			return base64Encoding;
		} catch (KNetException | KNetCommunicationServiceException e) {
			throw new KeyPairServiceException();
		}
	}

}
