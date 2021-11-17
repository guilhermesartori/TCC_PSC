package br.ufsc.tsp.service.utility;

import br.ufsc.labsec.valueobject.crypto.KNetRequester;
import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.exception.KNetException;

public class KeyManager {

	private final KNetRequester kNetRequester;

	/**
	 * @throws KNetException
	 * 
	 */
	public KeyManager(KNetRequester kNetRequester) throws KNetException {
		super();
		this.kNetRequester = kNetRequester;
	}

	public KeyIdentifierPair createKeyPair(String keyAlgorithm, String keyParameter, String keyName)
			throws KNetException {
		var keyIdentifierPair = kNetRequester.generateKeyPair(keyAlgorithm, keyParameter, keyName + "-private",
				keyName + "-public");
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
