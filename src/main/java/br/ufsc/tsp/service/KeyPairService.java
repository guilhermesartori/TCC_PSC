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
import br.ufsc.tsp.controller.request.KeyPairGenerationRequest;
import br.ufsc.tsp.controller.request.SignatureRequest;
import br.ufsc.tsp.domain.KeyPair;
import br.ufsc.tsp.exception.KeyPairDeletionException;
import br.ufsc.tsp.exception.KeyPairGenerationException;
import br.ufsc.tsp.exception.SignatureException;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.KeyPairRepository;
import br.ufsc.tsp.service.utility.KeyManager;

@Service
@Transactional
public class KeyPairService {

	private static final String KEY_NOT_FOUND_ERROR = "Key doesn't exist or doesn't belong to user.";

	private final AppUserRepository appUserRepository;
	private final KeyPairRepository keyPairRepository;
	private final KeyManager keyManager;

	/**
	 * 
	 * @param keyPairRepository
	 * @param appUserRepository
	 */
	@Autowired
	public KeyPairService(KeyPairRepository keyPairRepository, AppUserRepository appUserRepository,
			KeyManager keyManager) {
		super();
		this.keyPairRepository = keyPairRepository;
		this.appUserRepository = appUserRepository;
		this.keyManager = keyManager;
	}

	public List<KeyPair> getKeyPairs() {
		return keyPairRepository.findAll();
	}

	public void createKeyPair(String username, String encodingKey, KeyPairGenerationRequest request)
			throws KeyPairGenerationException {
		try {
			var keyAlgorithm = request.getKeyAlgorithm();
			var keyParameter = request.getKeyParameter();

			var identifiers = keyManager.createKeyPair(keyAlgorithm, keyParameter);

			var privateKeyIdentifier = identifiers.getPrivateKeyIdentifier();
			var publicKeyIdentifier = identifiers.getPublicKeyIdentifier();
			var uniqueIdentifier = generateUniqueIdentifier(privateKeyIdentifier, publicKeyIdentifier);
			var appUser = appUserRepository.findByUsername(username);

			var keyPairEntity = new KeyPair(privateKeyIdentifier, publicKeyIdentifier, keyAlgorithm, uniqueIdentifier,
					appUser);

			keyPairRepository.save(keyPairEntity);
		} catch (NoSuchAlgorithmException | KNetException e) {
			throw new KeyPairGenerationException();
		}
	}

	@Transactional
	public void deleteKeyPair(String username, String uniqueIdentifier) throws KeyPairDeletionException, KNetException {
		var user = appUserRepository.findByUsername(username);
		var optionalkeyPair = keyPairRepository.findKeyPairByOwnerAndUniqueIdentifier(user, uniqueIdentifier);
		if (optionalkeyPair.isEmpty())
			throw new KeyPairDeletionException(KEY_NOT_FOUND_ERROR);
		else {
			var keyPair = optionalkeyPair.get();
			keyManager.deleteKeyPair(keyPair.getPrivateKey(), keyPair.getPublicKey());
			keyPairRepository.deleteKeyPairByUniqueIdentifier(uniqueIdentifier);
		}
	}

	public String sign(String username, String encodingKey, SignatureRequest request) throws SignatureException,
			NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, KNetException {
		var user = appUserRepository.findByUsername(username);
		var optionalkeyPair = keyPairRepository.findKeyPairByOwnerAndUniqueIdentifier(user,
				request.getKeyUniqueIdentifier());
		if (optionalkeyPair.isEmpty())
			throw new SignatureException(KEY_NOT_FOUND_ERROR);

		var base64Decoder = Base64.getDecoder();
		var base64Data = request.getBase64EncodedData();
		var data = base64Decoder.decode(base64Data);

		var keyPair = optionalkeyPair.get();
		var signature = keyManager.sign(keyPair.getPrivateKey(), keyPair.getKeyAlgorithm(), data);
		var base64Encoder = Base64.getEncoder();
		var base64Signature = base64Encoder.encodeToString(signature);

		return base64Signature;
	}

	private String generateUniqueIdentifier(String privateKeyIdentifier, String publicKeyIdentifier)
			throws NoSuchAlgorithmException {
		var provider = new BouncyCastleProvider();
		var base64Encoder = Base64.getEncoder();
		var digest = MessageDigest.getInstance("SHA-256", provider);

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
