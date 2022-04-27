package br.ufsc.labsec.openpsc.service.exception;

public class KeyPairServiceException extends Exception {

	public enum ExceptionType {
		DEFAULT("Error during key generation."), KEY_NAME_IN_USE("Key name already in use."),
		KEY_NOT_FOUND("Key doesn't exist or doesn't belong to user.");

		private String message;

		/**
		 * @param message
		 */
		private ExceptionType(String message) {
			this.message = message;
		}

	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1796679617100229683L;

	/**
	 * 
	 */
	public KeyPairServiceException() {
		super(ExceptionType.DEFAULT.message);
	}

	public KeyPairServiceException(ExceptionType exceptionType) {
		super(exceptionType.message);
	}
}
