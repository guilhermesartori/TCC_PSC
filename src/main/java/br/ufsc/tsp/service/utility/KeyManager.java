package br.ufsc.tsp.service.utility;

import java.util.HashMap;
import java.util.Properties;

import org.springframework.context.annotation.Bean;

import br.ufsc.labsec.valueobject.crypto.KNetRequester;
import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.labsec.valueobject.kmip.KkmipClientBuilder;

public class KeyManager {

	private final KNetRequester kNetRequester;

	/**
	 * @throws KNetException
	 * 
	 */
	public KeyManager() throws KNetException {
		super();
		this.kNetRequester = new KNetRequester(KkmipClientBuilder.build(null, null, new HashMap<>()), null, null);
	}

	/**
	 * @throws KNetException
	 * 
	 */
	public KeyManager(KNetRequester kNetRequester) throws KNetException {
		super();
		this.kNetRequester = kNetRequester;
	}

	public KeyIdentifierPair createKeyPair(String keyAlgorithm, String keyParameter) throws KNetException {
		var keyIdentifierPair = kNetRequester.generateKeyPair(keyAlgorithm, keyParameter, "private-key-test",
				"public-key-test");
		return keyIdentifierPair;
	}

	public byte[] sign(String privateKeyUniqueIdentifier, String algorithm, byte[] data) throws KNetException {
		var signature = kNetRequester.sign(privateKeyUniqueIdentifier, algorithm, data);
		return signature;
	}

	public void deleteKeyPair(String privateKey, String publicKey) throws KNetException {
		kNetRequester.revokeAndDestroy(new String[] { privateKey, publicKey });
	}

}
