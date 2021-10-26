package br.ufsc.tsp.exception;

public class KeyPairGenerationException extends Exception {

	private static final String DEFAULT_MESSAGE = "Error during key generation.";

	/**
	 * 
	 */
	private static final long serialVersionUID = 1796679617100229683L;

	/**
	 * 
	 */
	public KeyPairGenerationException() {
		super(DEFAULT_MESSAGE);
	}

	/**
	 * 
	 * @param message
	 */
	public KeyPairGenerationException(String message) {
		super(message);
	}
}
