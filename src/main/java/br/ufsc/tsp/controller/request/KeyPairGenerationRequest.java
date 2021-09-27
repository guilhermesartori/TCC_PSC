package br.ufsc.tsp.controller.request;

public class KeyPairGenerationRequest {

	private String keyAlgorithm;
	private String keyParameter;

	/**
	 * @param keyAlgorithm
	 * @param keyParameter
	 */
	public KeyPairGenerationRequest(String keyAlgorithm, String keyParameter) {
		super();
		this.keyAlgorithm = keyAlgorithm;
		this.keyParameter = keyParameter;
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

}
