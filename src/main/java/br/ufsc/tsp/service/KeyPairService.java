package br.ufsc.tsp.service;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.transaction.Transactional;

import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.tsp.controller.request.KeyPairGenerationRequest;
import br.ufsc.tsp.controller.request.SignatureRequest;
import br.ufsc.tsp.domain.KeyPair;
import br.ufsc.tsp.domain.enums.KeyAlgorithmEnum;
import br.ufsc.tsp.exception.KeyPairDeletionException;
import br.ufsc.tsp.exception.KeyPairGenerationException;
import br.ufsc.tsp.exception.SignatureException;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.KeyPairRepository;

@Service
@Transactional
public class KeyPairService {

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
			var appUser = appUserRepository.findByUsername(username);

			var provider = new BouncyCastleProvider();
			var generator = KeyPairGenerator.getInstance(request.getKeyAlgorithm(), provider);
			var digest = MessageDigest.getInstance("SHA-256", provider);
			var base64Encoder = Base64.getEncoder();

			var keyAlgorithm = request.getKeyAlgorithm();

			AlgorithmParameterSpec keySpec;
			switch (KeyAlgorithmEnum.valueOf(keyAlgorithm)) {
			case EC:
				keySpec = new ECGenParameterSpec(request.getKeyParameter());
				generator.initialize(keySpec);
				break;
			case RSA:
				generator.initialize(Integer.parseInt(request.getKeyParameter()));
				break;
			case EDDSA:
				keySpec = new EdDSAParameterSpec(request.getKeyParameter());
				generator.initialize(keySpec);
				break;
			default:
				throw new KeyPairGenerationException("Invalid algorithm.");
			}
			var keyPair = generator.generateKeyPair();

			var encodedPrivateKey = keyPair.getPrivate().getEncoded();
			var base64EncodedPrivateKey = base64Encoder.encodeToString(encodedPrivateKey);

			var encodedPublicKey = keyPair.getPublic().getEncoded();
			var base64EncodedPublicKey = base64Encoder.encodeToString(encodedPublicKey);

			var publicAndPrivateKeyConcatenation = base64EncodedPublicKey + base64EncodedPrivateKey;

			var digested = digest.digest(publicAndPrivateKeyConcatenation.getBytes());
			var uniqueIdentifierBytes = Arrays.copyOf(digested, 64);
			var uniqueIdentifier = base64Encoder.encodeToString(uniqueIdentifierBytes);

			var keyPairEntity = new KeyPair(base64EncodedPrivateKey, base64EncodedPublicKey, keyAlgorithm,
					uniqueIdentifier, appUser);

			keyPairRepository.save(keyPairEntity);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyPairGenerationException("Invalid algorithm.");
		} catch (InvalidAlgorithmParameterException e) {
			throw new KeyPairGenerationException("Invalid parameter.");
		} catch (NumberFormatException e) {
			throw new KeyPairGenerationException("Invalid parameter.");
		}
	}

	@Transactional
	public void deleteKeyPair(String uniqueIdentifier) throws KeyPairDeletionException {
		if (!keyPairRepository.existsKeyPairByUniqueIdentifier(uniqueIdentifier))
			throw new KeyPairDeletionException("Key doesn't exist");
		else
			keyPairRepository.deleteKeyPairByUniqueIdentifier(uniqueIdentifier);
	}

	public String sign(SignatureRequest request) throws SignatureException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException, java.security.SignatureException {
		var optionalkeyPair = keyPairRepository.findKeyPairByUniqueIdentifier(request.getKeyUniqueIdentifier());
		if (optionalkeyPair.isEmpty())
			throw new SignatureException("Key doesn't exist.");
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
