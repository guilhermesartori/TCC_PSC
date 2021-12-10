package br.ufsc.tsp.service.exception;

public class KeyManagerException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8164927720607350111L;

	public enum ExceptionType {
		DEFAULT("KNet configuration not initialized.");

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
	public KeyManagerException() {
		super(ExceptionType.DEFAULT.message);
	}

	public KeyManagerException(ExceptionType exceptionType) {
		super(exceptionType.message);
	}

}
