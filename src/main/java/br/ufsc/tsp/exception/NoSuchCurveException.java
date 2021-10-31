package br.ufsc.tsp.exception;

public class NoSuchCurveException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2604200445123537988L;

	public NoSuchCurveException(String message) {
		super(message);
	}

	public NoSuchCurveException(String message, Throwable cause) {
		super(message, cause);
	}

	public NoSuchCurveException(Throwable cause) {
		super(cause);
	}
}
