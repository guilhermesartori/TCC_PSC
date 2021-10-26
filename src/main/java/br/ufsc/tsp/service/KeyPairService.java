package br.ufsc.tsp.service;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.transaction.Transactional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.tsp.controller.request.KeyPairGenerationRequest;
import br.ufsc.tsp.controller.request.SignatureRequest;
import br.ufsc.tsp.domain.KeyPair;
import br.ufsc.tsp.exception.KeyPairDeletionException;
import br.ufsc.tsp.exception.KeyPairGenerationException;
import br.ufsc.tsp.exception.SignatureException;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.KeyPairRepository;
import br.ufsc.tsp.service.utility.KeyGenerator;

@Service
@Transactional
public class KeyPairService {

	private static final String KEY_NOT_FOUND_ERROR = "Key doesn't exist or doesn't belong to user.";

	private final AppUserRepository appUserRepository;
	private final KeyPairRepository keyPairRepository;

	/**
	 * 
	 * @param keyPairRepository
	 * @param appUserRepository
	 */
	@Autowired
	public KeyPairService(KeyPairRepository keyPairRepository, AppUserRepository appUserRepository) {
		super();
		this.keyPairRepository = keyPairRepository;
		this.appUserRepository = appUserRepository;
	}

	public List<KeyPair> getKeyPairs() {
		return keyPairRepository.findAll();
	}

	public void createKeyPair(String username, KeyPairGenerationRequest request) throws KeyPairGenerationException {
		try {
			var keyAlgorithm = request.getKeyAlgorithm();
			var keyParameter = request.getKeyParameter();
			var keyGenerator = new KeyGenerator(keyAlgorithm, keyParameter);
			var keyPair = keyGenerator.generate();

			var encodedPrivateKey = keyPair.getPrivate().getEncoded();
			var base64Encoder = Base64.getEncoder();
			var base64EncodedPrivateKey = base64Encoder.encodeToString(encodedPrivateKey);
			var encodedPublicKey = keyPair.getPublic().getEncoded();
			var base64EncodedPublicKey = base64Encoder.encodeToString(encodedPublicKey);

			var provider = new BouncyCastleProvider();
			var digest = MessageDigest.getInstance("SHA-256", provider);
			var publicAndPrivateKeyConcatenation = base64EncodedPublicKey + base64EncodedPrivateKey;
			var digested = digest.digest(publicAndPrivateKeyConcatenation.getBytes());
			var uniqueIdentifierBytes = Arrays.copyOf(digested, 64);
			var uniqueIdentifier = base64Encoder.encodeToString(uniqueIdentifierBytes);

			var appUser = appUserRepository.findByUsername(username);
			var keyPairEntity = new KeyPair(base64EncodedPrivateKey, base64EncodedPublicKey, keyAlgorithm,
					uniqueIdentifier, appUser);

			keyPairRepository.save(keyPairEntity);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyPairGenerationException();
		}
	}

	@Transactional
	public void deleteKeyPair(String username, String uniqueIdentifier) throws KeyPairDeletionException {
		var user = appUserRepository.findByUsername(username);
		if (!keyPairRepository.existsKeyPairByOwnerAndUniqueIdentifier(user, uniqueIdentifier))
			throw new KeyPairDeletionException(KEY_NOT_FOUND_ERROR);
		else
			keyPairRepository.deleteKeyPairByUniqueIdentifier(uniqueIdentifier);
	}

	public String sign(String username, SignatureRequest request) throws SignatureException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException, java.security.SignatureException {
		var user = appUserRepository.findByUsername(username);
		var optionalkeyPair = keyPairRepository.findKeyPairByOwnerAndUniqueIdentifier(user,
				request.getKeyUniqueIdentifier());
		if (optionalkeyPair.isEmpty())
			throw new SignatureException(KEY_NOT_FOUND_ERROR);
		var provider = new BouncyCastleProvider();
		var keyPair = optionalkeyPair.get();
		var keyAlgorithm = keyPair.getKeyAlgorithm();
		var base64EncodedPrivateKey = keyPair.getPrivateKey();
		var base64Decoder = Base64.getDecoder();
		var encodedPrivateKey = base64Decoder.decode(base64EncodedPrivateKey);
		var privateKeySpec = new X509EncodedKeySpec(encodedPrivateKey);
		var keyFactory = KeyFactory.getInstance(keyAlgorithm, provider);
		var privateKey = keyFactory.generatePrivate(privateKeySpec);
		var signatureGenerator = Signature.getInstance(keyAlgorithm, provider);
		var base64Data = request.getBase64EncodedData();
		var data = base64Decoder.decode(base64Data);
		signatureGenerator.update(data);
		signatureGenerator.initSign(privateKey);
		var signature = signatureGenerator.sign();
		var base64Encoder = Base64.getEncoder();
		var base64Signature = base64Encoder.encodeToString(signature);
		return base64Signature;
	}

}
