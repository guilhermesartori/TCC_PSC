package br.ufsc.tsp.controller.request;

public class KeyPairGenerationRequest {

	private String keyAlgorithm;
	private String keyParameter;
	private String keyName;

	/**
	 * @param keyAlgorithm
	 * @param keyParameter
	 * @param keyName
	 */
	public KeyPairGenerationRequest(String keyAlgorithm, String keyParameter, String keyName) {
		super();
		this.keyAlgorithm = keyAlgorithm;
		this.keyParameter = keyParameter;
		this.keyName = keyName;
	}

	/**
	 * @return the keyAlgorithm
	 */
	public String getKeyAlgorithm() {
		return keyAlgorithm;
	}

	/**
	 * @return the keyParameter
	 */
	public String getKeyParameter() {
		return keyParameter;
	}

	/**
	 * @return the keyName
	 */
	public String getKeyName() {
		return keyName;
	}

}
