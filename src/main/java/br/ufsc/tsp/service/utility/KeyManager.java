package br.ufsc.tsp.service.utility;

import java.util.HashMap;

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

	public KeyIdentifierPair createKeyPair(String keyAlgorithm, String keyParameter) throws KNetException {
		var keyIdentifierPair = kNetRequester.generateKeyPair(keyAlgorithm, keyParameter, null, null);
		return keyIdentifierPair;
	}

	public byte[] sign(String privateKeyUniqueIdentifier, byte[] data) throws KNetException {
		var signature = kNetRequester.sign(privateKeyUniqueIdentifier, null, data);
		return signature;
	}

	public void deleteKeyPair(String privateKey, String publicKey) throws KNetException {
		kNetRequester.revokeAndDestroy(new String[] { privateKey, publicKey });
	}

}
