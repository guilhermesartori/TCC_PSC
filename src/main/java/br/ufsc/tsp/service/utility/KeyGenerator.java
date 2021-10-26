package br.ufsc.tsp.service.utility;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import br.ufsc.tsp.domain.enums.KeyAlgorithmEnum;
import br.ufsc.tsp.exception.KeyPairGenerationException;

public class KeyGenerator {

	private static final String INVALID_KEY_ALGORITHM_ERROR = "Invalid algorithm.";
	private static final String INVALID_KEY_PARAMETER_ERROR = "Invalid parameter.";

	private final Provider provider;
	private final String keyAlgorithm;
	private final String keyParameter;

	/**
	 * @param keyAlgorithm
	 * @param keyParameter
	 */
	public KeyGenerator(String keyAlgorithm, String keyParameter) {
		super();
		this.keyAlgorithm = keyAlgorithm;
		this.keyParameter = keyParameter;
		this.provider = new BouncyCastleProvider();
	}

	public KeyPair generate() throws KeyPairGenerationException {
		try {
			var generator = KeyPairGenerator.getInstance(keyAlgorithm, provider);

			AlgorithmParameterSpec keySpec;
			switch (KeyAlgorithmEnum.valueOf(keyAlgorithm)) {
			case EC:
				keySpec = new ECGenParameterSpec(keyParameter);
				generator.initialize(keySpec);
				break;
			case RSA:
				generator.initialize(Integer.parseInt(keyParameter));
				break;
			case EDDSA:
				keySpec = new EdDSAParameterSpec(keyParameter);
				generator.initialize(keySpec);
				break;
			default:
				throw new KeyPairGenerationException(INVALID_KEY_ALGORITHM_ERROR);
			}
			var keyPair = generator.generateKeyPair();
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			throw new KeyPairGenerationException(INVALID_KEY_ALGORITHM_ERROR);
		} catch (InvalidAlgorithmParameterException e) {
			throw new KeyPairGenerationException(INVALID_KEY_PARAMETER_ERROR);
		} catch (NumberFormatException e) {
			throw new KeyPairGenerationException(INVALID_KEY_PARAMETER_ERROR);
		}
	}

}
