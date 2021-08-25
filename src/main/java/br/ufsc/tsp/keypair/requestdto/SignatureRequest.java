package br.ufsc.tsp.keypair.requestdto;

public class SignatureRequest {

	private String keyUniqueIdentifier;
	private String hashingAlgorithm;
	private String base64EncodedData;

	/**
	 * @param keyUniqueIdentifier
	 * @param hashingAlgorithm
	 * @param base64EncodedData
	 */
	public SignatureRequest(String keyUniqueIdentifier, String hashingAlgorithm, String base64EncodedData) {
		super();
		this.keyUniqueIdentifier = keyUniqueIdentifier;
		this.hashingAlgorithm = hashingAlgorithm;
		this.base64EncodedData = base64EncodedData;
	}

	/**
	 * @return the keyUniqueIdentifier
	 */
	public String getKeyUniqueIdentifier() {
		return keyUniqueIdentifier;
	}

	/**
	 * @return the hashingAlgorithm
	 */
	public String getHashingAlgorithm() {
		return hashingAlgorithm;
	}

	/**
	 * @return the base64EncodedData
	 */
	public String getBase64EncodedData() {
		return base64EncodedData;
	}

}
