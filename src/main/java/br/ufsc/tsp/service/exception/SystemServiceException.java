package br.ufsc.tsp.service.exception;

public class SystemServiceException extends Exception {

	public enum ExceptionType {
		DEFAULT("Error submitting KNet configuration."), INVALID_KNET_CONFIG("Invalid KNet configuration.");

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
	public SystemServiceException() {
		super(ExceptionType.DEFAULT.message);
	}

	public SystemServiceException(ExceptionType exceptionType) {
		super(exceptionType.message);
	}
	
	public SystemServiceException(String message) {
		super(message);
	}

}
