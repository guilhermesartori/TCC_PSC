package br.ufsc.tsp.service.utility.kmip;

import java.security.PublicKey;

import br.ufsc.tsp.service.utility.KeyIdentifierPair;

public class GenerateAndGetResponse {
	private KeyIdentifierPair keyIdentifierPair;
	private PublicKey publicKey;

	public GenerateAndGetResponse() {
	}

	public GenerateAndGetResponse(KeyIdentifierPair keyIdentifierPair, PublicKey publicKey) {
		super();
		this.keyIdentifierPair = keyIdentifierPair;
		this.publicKey = publicKey;
	}

	public KeyIdentifierPair getKeyIdentifierPair() {
		return keyIdentifierPair;
	}

	public void setKeyIdentifierPair(KeyIdentifierPair keyIdentifierPair) {
		this.keyIdentifierPair = keyIdentifierPair;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

}
