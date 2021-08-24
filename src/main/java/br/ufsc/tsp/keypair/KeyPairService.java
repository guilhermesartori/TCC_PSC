package br.ufsc.tsp.keypair;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

import javax.transaction.Transactional;

import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.tsp.keypair.constant.KeyAlgorithmEnum;
import br.ufsc.tsp.keypair.exception.KeyPairDeletionException;
import br.ufsc.tsp.keypair.exception.KeyPairGenerationException;

@Service
public class KeyPairService {

	private final KeyPairRepository keyPairRepository;

	/**
	 * @param keyPairRepository
	 */
	@Autowired
	public KeyPairService(KeyPairRepository keyPairRepository) {
		super();
		this.keyPairRepository = keyPairRepository;
	}

	public List<KeyPair> getKeyPairs() {
		return keyPairRepository.findAll();
	}

	public void createKeyPair(KeyPairGenerationRequest request) throws KeyPairGenerationException {
		try {
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
			var uniqueIdentifierBytes = Arrays.copyOf(digested, 16);
			var uniqueIdentifier = base64Encoder.encodeToString(uniqueIdentifierBytes);

			var keyPairEntity = new KeyPair(base64EncodedPrivateKey, base64EncodedPublicKey, keyAlgorithm,
					uniqueIdentifier);

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

}
