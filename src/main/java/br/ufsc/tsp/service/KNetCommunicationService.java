package br.ufsc.tsp.service;

import java.security.PublicKey;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.labsec.valueobject.crypto.KNetRequester;
import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.labsec.valueobject.kmip.KkmipClientBuilder;
import br.ufsc.tsp.service.exception.KeyManagerException;

@Service
public class KNetCommunicationService {

	@Autowired
	private KNetRequester kNetRequester;

	public KNetCommunicationService() {
		super();
		final var props = System.getProperties();
		props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
	}

	public KeyIdentifierPair createKeyPair(String keyAlgorithm, String keyParameter, String keyName)
			throws KNetException, KeyManagerException {
		if (kNetRequester == null)
			throw new KeyManagerException();
		var keyIdentifierPair = kNetRequester.generateKeyPair(keyAlgorithm, keyParameter, keyName + "-private",
				keyName + "-public");
		return keyIdentifierPair;
	}

	public byte[] sign(String privateKeyUniqueIdentifier, String algorithm, byte[] data)
			throws KNetException, KeyManagerException {
		if (kNetRequester == null)
			throw new KeyManagerException();
		var signature = kNetRequester.sign(privateKeyUniqueIdentifier, algorithm, data);
		return signature;
	}

	public void deleteKeyPair(String privateKey, String publicKey) throws KNetException, KeyManagerException {
		if (kNetRequester == null)
			throw new KeyManagerException();
		kNetRequester.revokeAndDestroy(new String[] { privateKey, publicKey });
	}

	public PublicKey getPublicKey(String keyIdentifier, String keyAlgorithm) throws KNetException, KeyManagerException {
		if (kNetRequester == null)
			throw new KeyManagerException();
		return kNetRequester.getPublicKey(keyIdentifier, keyAlgorithm);
	}

	public void setKnetConfiguration(Map<String, String> parameters) throws KNetException {
		this.kNetRequester = new KNetRequester(KkmipClientBuilder.build(null, null, parameters),
				parameters.get("USERNAME"), parameters.get("PW"));
	}

}
