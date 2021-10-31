package br.ufsc.tsp.service.utility;

public class KeyIdentifierPair {

	private String publicKeyIdentifier;
	private String privateKeyIdentifier;

	public KeyIdentifierPair() {
		super();
	}

	public KeyIdentifierPair(String publicKeyIdentifier, String privateKeyIdentifier) {
		super();
		this.publicKeyIdentifier = publicKeyIdentifier;
		this.privateKeyIdentifier = privateKeyIdentifier;
	}

	public String getPublicKeyIdentifier() {
		return publicKeyIdentifier;
	}

	public void setPublicKeyIdentifier(String publicKeyIdentifier) {
		this.publicKeyIdentifier = publicKeyIdentifier;
	}

	public String getPrivateKeyIdentifier() {
		return privateKeyIdentifier;
	}

	public void setPrivateKeyIdentifier(String privateKeyIdentifier) {
		this.privateKeyIdentifier = privateKeyIdentifier;
	}

}
