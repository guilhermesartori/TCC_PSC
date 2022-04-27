package br.ufsc.labsec.openpsc.service;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

import br.ufsc.labsec.openpsc.entity.KeyPair;
import br.ufsc.labsec.openpsc.repository.AppUserRepository;
import br.ufsc.labsec.openpsc.repository.KeyPairRepository;
import br.ufsc.labsec.openpsc.service.exception.KNetCommunicationServiceException;
import br.ufsc.labsec.openpsc.service.exception.KeyPairServiceException;
import br.ufsc.labsec.openpsc.service.exception.KeyPairServiceException.ExceptionType;
import br.ufsc.labsec.valueobject.exception.KNetException;

@Service
@Transactional
public class KeyPairService {

	private final AppUserRepository appUserRepository;
	private final KeyPairRepository keyPairRepository;
	private final KNetCommunicationService kNetCommunicationService;
	private final MessageDigest digest;
	private final ParameterEncryptor parameterEncryptor;

	/**
	 * 
	 * @param keyPairRepository
	 * @param appUserRepository
	 */
	@Autowired
	public KeyPairService(KeyPairRepository keyPairRepository, AppUserRepository appUserRepository,
			KNetCommunicationService kNetCommunicationService, ParameterEncryptor parameterEncryptor) {
		super();
		this.keyPairRepository = keyPairRepository;
		this.appUserRepository = appUserRepository;
		this.kNetCommunicationService = kNetCommunicationService;
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
			if (keyPairRepository.findKeyPairByOwnerUsernameAndKeyName(username, keyName).isPresent())
				throw new KeyPairServiceException(ExceptionType.KEY_NAME_IN_USE);

			final var hsmKeyName = generateHsmKeyName(username, keyName);
			final var identifiers = kNetCommunicationService.createKeyPair(keyAlgorithm, keyParameter, hsmKeyName);

			final var privateKeyIdentifier = identifiers.getPrivateKeyIdentifier();
			final var publicKeyIdentifier = identifiers.getPublicKeyIdentifier();
			final var uniqueIdentifier = generateUniqueIdentifier(privateKeyIdentifier, publicKeyIdentifier);
			final var keyOwner = appUserRepository.findAppUserByUsername(username).get();

			final var encryptedPrivateKeyIdentifier = parameterEncryptor.encrypt(privateKeyIdentifier, accessKey);

			final var keyPairEntity = new KeyPair(publicKeyIdentifier, encryptedPrivateKeyIdentifier, keyAlgorithm,
					uniqueIdentifier, keyName, keyOwner);

			return keyPairRepository.save(keyPairEntity);
		} catch (NoSuchAlgorithmException | KNetException | IllegalArgumentException e) {
			throw new KeyPairServiceException();
		}
	}

	private String generateHsmKeyName(String username, String keyName) {
		try {
			final var secureRandom = SecureRandom.getInstanceStrong();
			final var concatenation = username + keyName + secureRandom.nextLong();
			final var digestedName = MessageDigest.getInstance("SHA256").digest(concatenation.getBytes());
			final var base64DigestedName = Base64.getEncoder().encodeToString(digestedName);
			return base64DigestedName;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public void deleteKeyPair(String username, String encodingKey, String uniqueIdentifier)
			throws KNetException, KeyPairServiceException, KNetCommunicationServiceException {
		final var optionalKeyPair = keyPairRepository.findKeyPairByOwnerUsernameAndUniqueIdentifier(username,
				uniqueIdentifier);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		else {
			final var keyPair = optionalKeyPair.get();
			final var privateKeyIdentifier = parameterEncryptor.decrypt(keyPair.getPrivateKey(), encodingKey);
			kNetCommunicationService.deleteKeyPair(privateKeyIdentifier, keyPair.getPublicKey());
			keyPairRepository.deleteKeyPairByUniqueIdentifier(uniqueIdentifier);
		}
	}

	public String sign(String username, String accessKey, String base64EncodedData, String keyUniqueIdentifier,
			String hashingAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
			KNetException, KeyPairServiceException, KNetCommunicationServiceException {
		final var optionalKeyPair = keyPairRepository.findKeyPairByOwnerUsernameAndUniqueIdentifier(username,
				keyUniqueIdentifier);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);

		final var base64Decoder = Base64.getDecoder();
		final var data = base64Decoder.decode(base64EncodedData);

		final var hashedData = MessageDigest.getInstance(hashingAlgorithm, new BouncyCastleProvider()).digest(data);

		final var keyPair = optionalKeyPair.get();
		final var privateKeyIdentifier = parameterEncryptor.decrypt(keyPair.getPrivateKey(), accessKey);
		final var signature = kNetCommunicationService.sign(privateKeyIdentifier, keyPair.getKeyAlgorithm(),
				hashedData);
		final var base64Encoder = Base64.getEncoder();
		final var base64Signature = base64Encoder.encodeToString(signature);

		return base64Signature;
	}

	private String generateUniqueIdentifier(String privateKeyIdentifier, String publicKeyIdentifier)
			throws NoSuchAlgorithmException {
		final var base64Encoder = Base64.getEncoder();

		final var encodedPrivateKey = privateKeyIdentifier.getBytes();
		final var encodedPublicKey = publicKeyIdentifier.getBytes();

		final var base64EncodedPrivateKey = base64Encoder.encodeToString(encodedPrivateKey);
		final var base64EncodedPublicKey = base64Encoder.encodeToString(encodedPublicKey);

		final var publicAndPrivateKeyConcatenation = base64EncodedPublicKey + base64EncodedPrivateKey;
		final var digested = digest.digest(publicAndPrivateKeyConcatenation.getBytes());
		final var uniqueIdentifierBytes = Arrays.copyOf(digested, 64);
		final var uniqueIdentifier = base64Encoder.encodeToString(uniqueIdentifierBytes);

		return uniqueIdentifier;
	}

	public KeyPair getKeyPair(String username, String keyUniqueIdentifier) throws KeyPairServiceException {
		final var optionalKeyPair = keyPairRepository.findKeyPairByOwnerUsernameAndUniqueIdentifier(username,
				keyUniqueIdentifier);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		return optionalKeyPair.get();
	}

	public KeyPair getKeyPairByKeyName(String username, String keyName) throws KeyPairServiceException {
		final var optionalKeyPair = keyPairRepository.findKeyPairByOwnerUsernameAndKeyName(username, keyName);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		return optionalKeyPair.get();
	}

	public boolean verifySignature(String keyUniqueIdentifier, String base64EncodedData, String base64EncodedSignature,
			String signatureAlgorithm) throws KeyPairServiceException, KNetException, KNetCommunicationServiceException,
			InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		final var optionalKeyPair = keyPairRepository.findKeyPairByUniqueIdentifier(keyUniqueIdentifier);
		if (optionalKeyPair.isEmpty())
			throw new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);

		final var keyPair = optionalKeyPair.get();
		final var algorithm = keyPair.getKeyAlgorithm();
		final var publicKeyIdentifier = keyPair.getPublicKey();
		final var publicKey = kNetCommunicationService.getPublicKey(publicKeyIdentifier, algorithm);

		final var data = Base64.getDecoder().decode(base64EncodedData);
		final var signature = Base64.getDecoder().decode(base64EncodedSignature);

		final var signatureVerifier = Signature.getInstance(signatureAlgorithm, new BouncyCastleProvider());
		signatureVerifier.initVerify(publicKey);
		signatureVerifier.update(data);
		return signatureVerifier.verify(signature);
	}

	public String getPublicKey(String keyIdentifier, String keyAlgorithm) throws KeyPairServiceException {
		try {
			final var publicKey = kNetCommunicationService.getPublicKey(keyIdentifier, keyAlgorithm);
			final var encodedPublicKey = publicKey.getEncoded();
			final var base64Encoding = Base64.getEncoder().encodeToString(encodedPublicKey);
			return base64Encoding;
		} catch (KNetException | KNetCommunicationServiceException e) {
			throw new KeyPairServiceException();
		}
	}

}
